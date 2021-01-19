package il.ac.idc.cs.sinkhole;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.HashSet;


public class SinkholeServer {

    // pointer for the data array that points to the next unread byte
    private static int m_BYTE_POINTER;
    // Offset pointers that point to the byte offset of the flag/ header they represent
    private static final int m_QR_BYTE_OFFSET = 2;
    private static final int m_RD_BYTE_OFFSET = 2;
    private static final int m_AA_BYTE_OFFSET = 2;
    private static final int m_RA_BYTE_OFFSET = 3;
    private static final int m_ERROR_BYTE_OFFSET = 3;
    private static final int m_NUM_ANSWERS_BYTE_OFFSET = 6;
    private static final int m_NUM_AUTHORITY_BYTE_OFFSET = 8;
    // error numbers for sending packet
    private static final byte m_ZER_ERROR_NUM = 0;
    private static final byte m_SERVER_ERROR_NUM = 2;
    private static final byte m_NAME_ERROR_NUM = 3;
    // udp port num
    private static final int m_UDP_PORT = 53;
    // flag to see if it replied in 16 iterations
    private static boolean m_GOT_ANSWER = false;
    //hashmap to check the names in blocklist
    private static final HashSet<String> m_BLOCKLIST = new HashSet<>();

    public static void main(String[] args) throws Exception {
        // if there is a blocklist try reading it
        if (args.length > 0) {
            try {
                blockListSet(args[0]);
            }catch (IOException io){
                System.err.println("Error reading blocklist file \n" + io.getMessage());
                return;
            }
        }
        //Buffers to hold the incoming datagram and the outgoing datagram
        byte[] receivedData = new byte[1024];

        // Binds port 5300 to socket on local host
        DatagramSocket serverSocket = new DatagramSocket(5300);

        while (true) {
            // Get random root server and get its IP
            String rootServer = getRandomRootServer();
            m_BYTE_POINTER = 0;

            // Set the IP address to the root server
            InetAddress ipAddress;
            try{
                ipAddress = InetAddress.getByName(rootServer);
            }
            catch(UnknownHostException ue){
                System.err.println(ue.getMessage());
                continue;
            }

            // Creates a datagram packet to receive data
            DatagramPacket receiveFromClientPacket = new DatagramPacket(receivedData, receivedData.length);

            // attempt to recieve the incoming datapacket
            try{
                serverSocket.receive(receiveFromClientPacket);
            }catch(IOException io){
                System.err.println(io.getMessage());
                continue;
            }

            // Flag handling //
            // Changes the RD flag to 0 while keeping all the other flags as they are
            receivedData[m_RD_BYTE_OFFSET] = (byte) (receivedData[m_RD_BYTE_OFFSET] & ((byte) -2));// -2 = 1111 1110

            // Saves the client's IP and port for future reply
            InetAddress clientIpAddress = receiveFromClientPacket.getAddress();
            int clientPort = receiveFromClientPacket.getPort();

            // resize the data array to the proper size
            byte[] sendOriginalData = Arrays.copyOfRange(receivedData, 0, receiveFromClientPacket.getLength());

            // check if the name is in the block list before sending to the root server
            // check if original has error
            boolean haveNoErr = hasNoError(String.format("%x", sendOriginalData[m_ERROR_BYTE_OFFSET]));
            //skip the flags
            m_BYTE_POINTER += 12;
            // if you have an error send the packet with the original error
            if(!haveNoErr){
                sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_ZER_ERROR_NUM);
                continue;
            }

            if(args.length > 0){
                //get question name
                String questionName = labelHandler(sendOriginalData, m_BYTE_POINTER, false);
                // if the question name is in the blocklist send name error and continue
                if (isInBlockList(questionName.substring(0, questionName.length() - 1))) {
                    sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_NAME_ERROR_NUM);
                    System.err.println("Packet in block list");
                    continue;
                }
            }

            // Creating a datagram packet to send
            DatagramPacket sendToRootServerPacket = new DatagramPacket(sendOriginalData, sendOriginalData.length, ipAddress, m_UDP_PORT);

            // Sent the data to the root server
            try{
                serverSocket.send(sendToRootServerPacket);
            }catch (IllegalArgumentException | IOException e){
                System.err.println(e.getMessage());
                sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_SERVER_ERROR_NUM);
                continue;
            }

            for (int i = 0; i < 16; i++) {
                m_GOT_ANSWER = false;
                receivedData = new byte[1024];

                // Gets the next response
                DatagramPacket responsePacket = new DatagramPacket(receivedData, receivedData.length);

                // Halts until the query has been received from authority
                try{
                    serverSocket.receive(responsePacket);
                }catch(IOException io){
                    System.err.println(io.getMessage());
                    sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_SERVER_ERROR_NUM);
                    break;
                }

                // Resize the data received accordingly to its size
                receivedData = Arrays.copyOfRange(receivedData, 0, responsePacket.getLength());

                // Readjust the pointer to the beginning
                m_BYTE_POINTER = 0;

                // Handling, reading and saving all the headers total of 12 bytes or 6 shorts
                int numAnswers = shortToInt(receivedData[m_NUM_ANSWERS_BYTE_OFFSET], receivedData[m_NUM_ANSWERS_BYTE_OFFSET + 1]);
                int numAuth = shortToInt(receivedData[m_NUM_AUTHORITY_BYTE_OFFSET], receivedData[m_NUM_AUTHORITY_BYTE_OFFSET + 1]);
                // checks if the error byte represents an error z
                haveNoErr = hasNoError(String.format("%x", receivedData[m_ERROR_BYTE_OFFSET]));

                // Advances the pointer in order to skip the flags
                m_BYTE_POINTER += 12;

                if (haveNoErr) {
                    if (numAnswers == 0 && numAuth > 0) {
                        // Init a byte to use when we read the data
                        byte b;
                        // Skipping over the question name part
                        String questionName = labelHandler(receivedData, m_BYTE_POINTER, false);

                        // if the question name is in the blocklist send name error and break
                        if (args.length > 0 && isInBlockList(questionName.substring(0, questionName.length() - 1))) {
                            m_GOT_ANSWER = true;
                            sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_NAME_ERROR_NUM);
                            break;
                        }

                        // Skipping the Question Type (2 bytes) and Question Class (2 bytes) total of 4 bytes
                        m_BYTE_POINTER += 4;

                        /*### Dealing with Authority ###*/
                        // Reading the next unread byte which will tell us whether we need to handle a pointer or label
                        // this reads the auth name part which is not used by us
                        b = receivedData[m_BYTE_POINTER++];
                        if (checkIfPointer(b)) {
                            // Reads the second byte in the pointer octet = 1 byte
                            m_BYTE_POINTER++;
                        } else {
                            // Go to previous byte
                            m_BYTE_POINTER--;
                            labelHandler(receivedData, m_BYTE_POINTER, false);
                        }

                        // Reading and Skipping over, type (2 bytes), class(2 bytes), ttl(4 bytes), rdlenth(2 bytes) total of 10 bytes
                        m_BYTE_POINTER += 10;

                        // Getting the first name server from authority
                        String respectMyAuthorityah = labelHandler(receivedData, m_BYTE_POINTER, false);

                        // Set the new IP address
                        InetAddress nameServerAddress;
                        try {
                            nameServerAddress = InetAddress.getByName(respectMyAuthorityah);
                        }
                        catch (UnknownHostException ue){
                            m_GOT_ANSWER = true;
                            sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_SERVER_ERROR_NUM);
                            break;
                        }

                        // create the next queryPacket
                        DatagramPacket queryPacket = new DatagramPacket(sendOriginalData, sendOriginalData.length, nameServerAddress, m_UDP_PORT);

                        try{
                            serverSocket.send(queryPacket);
                        }catch (IllegalArgumentException | IOException e){
                            m_GOT_ANSWER = true;
                            System.err.println(e.getMessage());
                            sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_SERVER_ERROR_NUM);
                            break;
                        }


                    }
                    // enter here when auth =0 and or ans > 0
                    else {
                        m_GOT_ANSWER = true;
                        // initiate with no error
                        byte errorNum = m_ZER_ERROR_NUM;

                        // if it no auth and no ans then return upate the nxdomain flag for sending
                        if (numAuth == 0 && numAnswers == 0){
                            errorNum = m_NAME_ERROR_NUM;
                        }

                        // send the answer
                        sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, errorNum);
                        break;
                    }
                }
                // enters the else if the packet has an error:
                else {
                    m_GOT_ANSWER = true;
                    // in the event of an error , update all the flags and keep the original error flag , and return to client.
                    // send with error num 0 --> this will keep original error when sending
                    sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_NAME_ERROR_NUM);
                    break;
                }
            }

            // if 16 iterations passed then send a serverfailure error
            if(!m_GOT_ANSWER){
                sendPacketToClient(sendOriginalData, clientIpAddress, clientPort, serverSocket, m_SERVER_ERROR_NUM);
                System.err.println("Didnt not get answer in 16 iterations");
            }
        }
    }


    /**
     * This method updates the data flags and sends it to client with the wanted changes
     * @param sendData - byte aarray representing the data to send
     * @param address - the ip adress of the client
     * @param portNum - the clients port num
     * @param serverSocket - the server socket that will send the data
     * @param errorNum - the error num to update in the error flags
     */
    private static void sendPacketToClient(byte[] sendData, InetAddress address, int portNum, DatagramSocket serverSocket, byte errorNum){
        // update the flags for sending
        byte[] updatedData = sendData;

        // unset up flag AA
        updatedData[m_AA_BYTE_OFFSET] = (byte) (updatedData[m_AA_BYTE_OFFSET] & (byte) 0xFB);
        // light up RD
        updatedData[m_RD_BYTE_OFFSET] = (byte) (updatedData[m_RD_BYTE_OFFSET] | (byte) 0x1);
        // light up flag QR
        updatedData[m_QR_BYTE_OFFSET] = (byte) (updatedData[m_QR_BYTE_OFFSET] | (byte) 0x80);
        // light up flag RA
        updatedData[m_RA_BYTE_OFFSET] = (byte) (updatedData[m_RA_BYTE_OFFSET] | (byte) 0x80);
        // light data error according to errroNum
        sendData[m_ERROR_BYTE_OFFSET] = (byte) (sendData[m_ERROR_BYTE_OFFSET] | errorNum);
        //create new packet for sending
        DatagramPacket queryPacket = new DatagramPacket(sendData, sendData.length, address, portNum);

        try {
            serverSocket.send(queryPacket);
        }catch (Exception e){
            System.err.println(" Unable to send exception to client \n " + e.getMessage());
        }
    }

    /**
     * This methods gets 2 bytes and get the short num they represent
     *
     * @param firstByte   - first byte
     * @param secondByte- second byte
     * @return int variable representing the 2 bytes
     */
    private static int shortToInt(byte firstByte, byte secondByte) {
        int ans;

        ans = (Byte.toUnsignedInt(firstByte) & 0x000000ff) << 8;
        ans += (Byte.toUnsignedInt(secondByte) & 0x000000ff);

        return ans;
    }

    /**
     * This method return true if the byte given is the begining of a pointer
     *
     * @param b - the first byte to start
     * @return true if it is the beginning of a pointer, false otherwise
     */
    private static boolean checkIfPointer(byte b) {
        boolean ans = true;
        int unsignedByte = Byte.toUnsignedInt(b);

        if (unsignedByte < 192) {
            ans = false;
        }

        return ans;
    }

    /**
     * This method handles reading labels.
     * there are 2 options:
     * 1. label ends with 0x0
     * 2. label ends with pointer
     * <p>
     * the method reads through the label until reaching either a pointer or 0x0.
     * if a 0 byte was read then the address that was read is returned
     * <p>
     * if a pointer byte was read, that is the unsigned byte is >= 192, then the offset is calculated and
     * pointer handler is invoked. the recieved address suffix is concatenated to the current address and returned
     * <p>
     * the global data pointer is updated accordingly
     * <p>
     * IMPORTANT: THE RETURNED STRING HAS A . IN THE END - TO BE REMOVED BY USER
     *
     * @param i_recievedData    - a byte array containing all the data
     * @param i_arrPointer      - a number acting as a pointer for the {@param recivedData} array
     * @param i_callFromPointer - a boolean variable that states weather the method was invoked from a pointer (if so, true)
     * @return a string of the read address (with a . in the end)
     */
    private static String labelHandler(byte[] i_recievedData, int i_arrPointer, boolean i_callFromPointer) {
        StringBuilder addressBuilder = new StringBuilder();
        byte b;
        byte numToRead;
        boolean isPointer = false;
        int pointer = (i_callFromPointer) ? i_arrPointer : m_BYTE_POINTER;

        try {
            // gets the amount of letters to read
            numToRead = i_recievedData[pointer++];

            while (numToRead != 0 && !isPointer) {
                for (int j = 0; j < numToRead; j++) {
                    b = i_recievedData[pointer++];
                    addressBuilder.append((char) (b));
                }
                addressBuilder.append('.');
                numToRead = i_recievedData[pointer++];

                if (checkIfPointer(numToRead)) {
                    isPointer = true;
                }
            }

            if (isPointer) {
                int offset = calcOffset(Byte.toUnsignedInt(numToRead), Byte.toUnsignedInt(i_recievedData[pointer++]));

                String suffixLabel = pointerHandler(offset, i_recievedData);
                addressBuilder.append(suffixLabel);
            }

            // update the global pointer
            if (!i_callFromPointer) {
                m_BYTE_POINTER = pointer;
            }

        } catch (Exception e) {
            System.err.println("label handler failed, stream finished");
        }

        return addressBuilder.toString();
    }

    /**
     * This method handles pointer label reads.
     *
     * @param offset       - the offset of where the label is in the data
     * @param recievedData - byte array of the data
     * @return the string representation of the label it is pointing to.
     */
    private static String pointerHandler(int offset, byte[] recievedData) {
        return labelHandler(recievedData, offset, true);
    }

    /**
     * This method gets 2 unsigned bytes and calculates the offset
     *
     * @param firstUnsignedByteAsInt  - first unsigned byte saved in an int
     * @param secondUnsignedByteAsInt - second unsigned byte saved in an int
     * @return the offset the 2 bytes represent
     */
    private static int calcOffset(int firstUnsignedByteAsInt, int secondUnsignedByteAsInt) {
        int offset = (firstUnsignedByteAsInt - 192) << 8;
        offset = offset | secondUnsignedByteAsInt;

        return offset;
    }

    /***
     * This method returns a random root servers Inet address
     * @return random Inet hostname
     */
    public static String getRandomRootServer() {
        // gets a letter from a - m
        char letter = (char) ((int) (Math.random() * ('m' - 'a' + 1) + 'a'));

        return letter + ".root-servers.net";
    }

    /**
     * This method checks if the RCODE returns a no error response (last byte is 0)
     *
     * @param hexNum: the hexadecimal representation of the flags header
     * @return true if there is a no error response, false otherwise.
     */
    private static boolean hasNoError(String hexNum) {
        boolean ans = false;

        if (hexNum.endsWith("0")) {
            ans = true;
        }

        return ans;
    }

    /**
     * NEW METHOD ADDED
     * This method reads the blocklist file and adds all the sites into this list
     *
     * @param fileName - the file of the blocklist
     *                 SIDE EFFECT     - This method changes the values of the Set
     */
    private static void blockListSet(String fileName) throws IOException {
        int c;
        StringBuilder sb = new StringBuilder();
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(fileName);
            c = fis.read();
            while (c != -1) {
                while (c != '\n') {
                    sb.append((char) c);
                    c = fis.read();
                }
                m_BLOCKLIST.add(sb.toString());
                sb = new StringBuilder();
                c = fis.read();
            }
        } catch (FileNotFoundException fnfe) {
            System.err.println("No such file");
        } catch (IOException ioe) {
            System.err.println("IO Exception");
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }


    /**
     * NEW METHOD
     * This method checks whether a certain question is in the block list
     *
     * @param question - the question received from DNS query
     * @return if the question is in the set
     */
    private static boolean isInBlockList(String question) {
        return m_BLOCKLIST.contains(question);
    }
}
