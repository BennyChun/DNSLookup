package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.FileOutputStream;
import java.net.*;
import java.time.OffsetDateTime;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    private static byte[] eQuery;
    private static byte[] queryID;

    private static int qCount;
    private static int answerCount;
    private static int nsCount;
    private static int indirectionLevel;

    private static ResourceRecord decodedRecord;
    private static int byteOffset;
    private static Boolean isAuthoritative;
    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;

            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
       retrieveResultsFromServer(node, rootServer);
        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] responsePacket;
        byte[] sendData;

        // encode the query
        eQuery = encodeQuery(node);

        responsePacket = sendQuery(node, server);

        decodedRecord = decodeQuery(responsePacket);

        // recursively search for the next DNS
        if (answerCount == 1) {
            cache.addResult(decodedRecord);
        } else {
            Boolean flag = true;
            while (flag && qCount <= 10) {
                if (isAuthoritative & answerCount == 0) {
                    System.out.println(node.getHostName() + " A -6 0.0.0.0");
                    break;
                }
                if (answerCount > 0) {
                    if (decodedRecord.getType().getCode() == 1 || decodedRecord.getType().getCode() == 28) {
                        flag = false;
                    } else if (decodedRecord.getType().getCode() == 5) {
                        try {
                            indirectionLevel++;
                            getResults(decodedRecord.getNode(), indirectionLevel);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        try {
                            findAndPrintResults(decodedRecord.getHostName(), decodedRecord.getType());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        qCount++;
                    }
                    else {
                        break;
                    }
                } else {
                    if (decodedRecord != null) {
                        if (decodedRecord.getInetResult() == null && decodedRecord.getTextResult().length() > 0) {
                            try {
                                getResults(decodedRecord.getNode(), indirectionLevel++);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            retrieveResultsFromServer(node, decodedRecord.getInetResult());
                        }
                        qCount++;
                    }
                    // make sure queries dont exceed 10
                    if (qCount > 10) {
                        flag = false;
                    }
                }
                // add the record to the cache
                if (decodedRecord.getHostName() == node.getHostName()) {
                    cache.addResult(decodedRecord);
                }
            }
        }
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    /**
     * This method sends the encoded query and returns the non decoded response
     * @param node the node that needs to be queried
     * @param server the server to be queried
     * @return the response from the servers
     */
    private static byte[] sendQuery(DNSNode node, InetAddress server){

        // getting response
        byte[] sData = eQuery;
        byte[] rData = new byte[1024];

        DatagramPacket sPacket = new DatagramPacket(sData, sData.length, server, DEFAULT_DNS_PORT);
        DatagramPacket rPacket = new DatagramPacket(rData, rData.length);
        try{
            socket.send(sPacket);
            socket.receive(rPacket);
        }catch (Exception e){
            System.out.println(node.getHostName() + " A" + "     -2" + "       0.0.0.0");
            try{
                socket.send(sPacket);
                socket.receive(rPacket);
            }catch(Exception ex){

            }
        }

        byte[] rBytes = rPacket.getData();

        return rBytes;

    }
    /**
     * This method encodes the query that needs to be sent into a byte array
     * @param node the DNS query that needs to be encoded
     */
    private static byte[] encodeQuery(DNSNode node){
        eQuery = new byte[512];
        // generate query ID
        queryID = new byte[2];
        random.nextBytes(queryID);

        // set query ID
        eQuery[0] = queryID[0];
        eQuery[1] = queryID[1];
        // QR, Opcode, AA, TC, RD. RA, Z, RCODE
        for(int i = 2; i < 4; i++) {
            eQuery[i] = 0x00;
        }
        // QDCOUNT
        eQuery[4] = 0x00;
        eQuery[5] = 0x01;
        // ANCOUNT & NSCOUNT & ARCOUNT
        for(int i = 6; i < 12; i++) {
            eQuery[i] = 0x00;
        }

        // QNAME
        int ptr = 12;
        String[] fields = node.getHostName().split("\\.");
        for (int i=0; i< fields.length;i++){
            String field = fields[i];
            int length = field.length();
            eQuery[ptr++] = (byte) length;
            for (Character ch: field.toCharArray()){
                eQuery[ptr++] = (byte) ((int) (ch));
            }
        }

        // QNAME suffix
        eQuery[ptr++] = 0x00;
        // QTYPE
        eQuery[ptr++] = 0x00;
        if (node.getType().getCode() == 28){
            eQuery[ptr++] = 0x1c;
        } else{
            eQuery[ptr++] = 0x01;
        }
        // QCLASS
        eQuery[ptr++] = 0x00;
        eQuery[ptr++] = 0x01;
        return eQuery;
    }

    /**
     * This method is for decoding the response from the server to obtain
     * the details of the record.
     *
     * @param serverResponse the response obtained after sending off the query
     * @return ResourseRecord a record containing the decoded response stored in a
     *                          ResourceRecord object
     */
    private static ResourceRecord decodeQuery(byte[] serverResponse){
        int responseQueryID = bytesToInt(serverResponse, 0, 2);
        qCount = 1;
        answerCount = bytesToInt(serverResponse, 6, 2);
        nsCount = bytesToInt(serverResponse, 8, 2);
        int aCount = bytesToInt(serverResponse, 10, 2);
        int offset = 12;
        while (serverResponse[offset] != 0) {
            ++offset;
        }
        int qType = bytesToInt(serverResponse, offset + 1, 2);
        int qClass = bytesToInt(serverResponse, offset + 3, 2);

        if (answerCount >= 1 || qType == 6) {
            isAuthoritative = true;
        } else {
            isAuthoritative = false;
        }

        int totCount = nsCount + aCount + answerCount;
        ArrayList<ResourceRecord> resourceList = new ArrayList<ResourceRecord>();
        // getting bytes for
        offset += 5;
        for (int i = 0; i < totCount; i++) {
            ResourceRecord record = readRR(serverResponse, offset);
            offset = byteOffset;
            byteOffset = 0;
            if (record.getType().getCode() == 6){
                isAuthoritative = true;
            }  else{
                isAuthoritative = false;
            }
            //check if tracing is on
            if (verboseTracing){
                verbosePrintResourceRecord(record, record.getType().getCode());
            }
            resourceList.add(record);
        }
        for (int i = 0; i < resourceList.size(); i++){
            if (answerCount >= 1){
                return resourceList.get(0);
            } else{
                if (resourceList.get(i).getType().getCode() == 1){
                    return resourceList.get(i);
                } else if(resourceList.get(i).getType().getCode() == 6){
                    isAuthoritative = true;
                    return resourceList.get(i);
                }
            }
        }
        return resourceList.get(0);
    }

    /**
     * This method converts bytes in a byte array into an integer.
     * @param arr byte array containing the response bytes
     * @param offset the offset for the bytes that need to be converted
     * @param num number of bytes that need to be converted
     * @return int the integer that has been converted
     */
    private static int bytesToInt(byte[] arr, int offset, int num) {
        if(offset>arr.length-1){
            return 0;
        }

        if (num == 2) {
            return (arr[offset] & 0xFF) << 8 | (arr[offset + 1] & 0xFF);
        } else if (num == 4){
            return (arr[offset] << 24) | (arr[offset + 1] & 0xFF) << 16 | (arr[offset + 2] & 0xFF) << 8 | (arr[offset + 3] & 0xFF);
        }
        return 0;
    }

    /**
     * This method reads the non decoded bytes from the server response
     * and returns a resource record containing the vital portions of the
     * resource record.
     *
     * @param serverResponse the non decoded bytes from the server
     * @param offset offset used to keep track of which bytes are being converted
     * @return a ResourceRecord object containing the information required to
     *          get a reply for the lookup query
     */
    private static ResourceRecord readRR(byte[] serverResponse, int offset) {
        InetAddress ipAddress = null;
        String responseIPAddress = "";
        String name = "";
        String text = "";

        try {
            name = new String(returnName(serverResponse, offset));
            text = new String(returnName(serverResponse, offset + 11));
        } catch (Exception e) {

        }
        // get type
        int type = bytesToInt(serverResponse, offset + 2, 2);
        // skip classInt as not required
        offset += 4;
        // get ttl
        long ttl = bytesToInt(serverResponse, offset, 4);
        // get length of the record
        int recordLength = bytesToInt(serverResponse, offset + 6, 2);
        // get offset
        offset += 12;
        // if the record id an ipv 4 address
        if(type == 1 && recordLength == 4){
            byte[] responseIP = new byte[4];
            for(int i = 0; i < recordLength; i++){
                responseIP[i] = serverResponse[offset + i];
            }
            try{
                responseIPAddress = InetAddress.getByAddress(responseIP).toString().replaceAll("[/ ]", "");
            } catch(Exception e){
            }
        }
        // if the record is an ipv6 address
        if(type == 28 && recordLength == 16){
            byte[] responseIP = new byte[16];
            System.arraycopy(serverResponse, offset, responseIP, 0, 16);
            try{
                responseIPAddress = Inet6Address.getByAddress(responseIP).toString().replaceAll("[/ ]", "");
            } catch(Exception e){
            }
        } else {
            for (int i = 0; i < recordLength && i + offset < serverResponse.length; i++){
                int responseIP = serverResponse[offset + i];
                responseIPAddress = responseIP + ".";
            }
            try{
                responseIPAddress = InetAddress.getByName(responseIPAddress.substring(0, responseIPAddress.length() - 1)).toString().replaceAll("[/ ]","");
            } catch(Exception e){
            }
        }
        byteOffset = recordLength + 12;
        ResourceRecord responseRecord;
        try{
            ipAddress = InetAddress.getByName(name);
        } catch(UnknownHostException e){
        }
        if (ipAddress != null){
            responseRecord =  new ResourceRecord(name.trim(), RecordType.getByCode(type), ttl, ipAddress);
        } else {
            responseRecord =  new ResourceRecord(name.trim(), RecordType.getByCode(type), ttl, responseIPAddress);
        }
        return responseRecord;
    }

    /**
     * This method uses the server response to
     *
     * @param serverResponse
     * @param count
     * @return
     */
    private static byte[] returnName(byte[] serverResponse, int count) {
        byte[] name = new byte[512];

        int flag = 0;
        while (true) {
            if ((serverResponse[count] & 0xFF) == 0) {
                return name;

            }
            if ((serverResponse[count] & 0xFF) == 192) {
                count = serverResponse[count + 1];
                continue;
            }
            if (serverResponse[count] > 40) {
                name[flag++] = serverResponse[count++];

                continue;
            } else {
                if ( flag != 0) {
                    name[flag++] = 0x2e;
                    ++count;
                    continue;
                }
                ++count;
            }
        }
    }
}


