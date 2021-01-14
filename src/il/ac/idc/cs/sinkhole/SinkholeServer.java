package il.ac.idc.cs.sinkhole;


import java.net.*;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

/*
- Address Mapping record (A Record)—also known as a DNS host record, stores a hostname and its corresponding IPv4 address
    -   Name is host name
    -   Value is IP address
-this is the flow:
    while true
    send packet to root server
    recieve packet
    if all the flags are ok (see 3 in pdf) then continue (
        - וב זה יכול לקרות חח, אבל בגדול, התשובות מגיעות לפני ה-authority אז תכלס, אם מצאתם תשובה ויש עוד authority, רק תחזירו תשובה פשוט

    then run in a for loop i<16 unitl get answer
 */


public class SinkholeServer {

    // Points to the next unread byte
    private static int m_BYTE_POINTER;

    // Offset pointers
    private static final int m_FLAGS_FLAGS_OFFSET = 16;
    private static final int m_RD_BYTE_OFFSET = 2;
    private static final int m_AA_BYTE_OFFSET = 2;
    private static final int m_RA_BYTE_OFFSET = 3;
    private static final int m_ERROR_BYTE_OFFSET = 3;
    private static final int m_NUM_ANSWERS_BYTE_OFFSET = 6;
    private static final int m_NUM_AUTHORITY_BYTE_OFFSET = 8;
    private static final int m_UDP_PORT = 53;

    public static void main(String[] args) throws Exception {
        //Buffers to hold the incoming datagram and the outgoing datagram
        byte[] receivedData = new byte[1024];

        // Binds port 5300 to socket on local host
        DatagramSocket serverSocket = new DatagramSocket(5300);

        while (true) {
            // Get random root server and get its IP
            String rootServer = getRandomRootServer();
            System.out.println(rootServer);

            // Set the IP address to the root server
            // TODO CHECK B
            InetAddress ipAddress = InetAddress.getByName(rootServer);

            // Creates a datagram packet to receive data
            DatagramPacket receiveFromClientPacket = new DatagramPacket(receivedData, receivedData.length);

            // halts until query received
            serverSocket.receive(receiveFromClientPacket);
            System.out.println("received first packet");

            // Flag handling //
            // Changes the RD flag to 0 while keeping all the other flags as they are
            receivedData[m_RD_BYTE_OFFSET] = (byte) (receivedData[m_RD_BYTE_OFFSET] & ((byte) -2));// -2 = 1111 1110

            // resize the data array to the proper size
            byte[] sendOriginalData = Arrays.copyOfRange(receivedData, 0, receiveFromClientPacket.getLength());

            // Creating a datagram packet to send
            DatagramPacket sendToRootServerPacket = new DatagramPacket(sendOriginalData, sendOriginalData.length, ipAddress, m_UDP_PORT);

            // Saves the client's IP and port for future reply
            InetAddress clientIpAddress = receiveFromClientPacket.getAddress();
            int clientPort = receiveFromClientPacket.getPort();

            // send
            serverSocket.send(sendToRootServerPacket);
            System.out.println("sent first response\n");

            for (int i = 0; i < 16; i++) {
                receivedData = new byte[1024];

                // Gets the next response
                DatagramPacket responsePacket = new DatagramPacket(receivedData, receivedData.length);

                // Halts until the query has been received from authority
                serverSocket.receive(responsePacket);

                //resize the data
                receivedData = Arrays.copyOfRange(receivedData, 0, responsePacket.getLength());

                // Readjust the pointer to the beginning
                m_BYTE_POINTER = 0;
                System.out.println("received packet " + i);


                // Handling, reading and saving all the headers total of 12 bytes or 6 shorts
                int numAnswers = shortToInt(receivedData[m_NUM_ANSWERS_BYTE_OFFSET], receivedData[m_NUM_ANSWERS_BYTE_OFFSET + 1]);
                int numAuth = shortToInt(receivedData[m_NUM_AUTHORITY_BYTE_OFFSET], receivedData[m_NUM_AUTHORITY_BYTE_OFFSET + 1]);
                boolean haveNoErr = hasNoError(String.format("%x", receivedData[m_ERROR_BYTE_OFFSET]));
                System.out.println("number of answers: " + numAnswers);
                System.out.println("number of authority: " + numAuth);
                System.out.println("is it error free? " + haveNoErr);

                // advance the pointer to skip the flags
                m_BYTE_POINTER += 12;

                if (haveNoErr) {
                    if (numAnswers == 0 && numAuth > 0) {
                        // Init a byte to use when we read the data
                        byte b;
                        // Skipping over the question name part (ends in 0x0)
                        labelHandler(receivedData, m_BYTE_POINTER, false);
                        // Skipping the Question Type (2 bytes) and Question Class (2 bytes) total of 4 bytes
                        m_BYTE_POINTER += 4;
                        System.out.println("finished question section");

                        /* Dealing with Authority */

                        // Reading the next unread byte which will tell us whether we handle a pointer or header
                        b = receivedData[m_BYTE_POINTER++];
                        if (checkIfPointer(b)) {
                            // Reads the second byte in the octet = 1 byte
                            m_BYTE_POINTER++;
                        } else {
                            // Go to previous byte
                            m_BYTE_POINTER--;
                            // skip over the auth name part
                            labelHandler(receivedData, m_BYTE_POINTER, false);
                        }

                        // Reading and Skipping over, type (2 bytes), class(2 bytes), ttl(4 bytes), rdlenth(2 bytes) total of 10 bytes
                        m_BYTE_POINTER += 10;

                        // Getting the first name server from authority
                        String respectMyAuthorityah = labelHandler(receivedData, m_BYTE_POINTER, false);

                        System.out.println("First Name Server is: " + respectMyAuthorityah);

                        // Set the new IP by getting it's name
                        InetAddress nameServerAddress = InetAddress.getByName(respectMyAuthorityah);

                        System.out.println(nameServerAddress);

                        // setting the next queryPacket
                        DatagramPacket queryPacket = new DatagramPacket(sendOriginalData, sendOriginalData.length, nameServerAddress, m_UDP_PORT);
                        serverSocket.send(queryPacket);
                        System.out.println("sent response " + i + "\n");

                    } else{
                        if (numAnswers > 0) {
                            System.out.println("Answer received");
                            // TODO CHECK IF WE NEED TO CHANGE FLAG RD
                            //light up RD
                            //sendOriginalData[m_RD_BYTE_OFFSET] = (byte)(sendOriginalData[m_RD_BYTE_OFFSET] | (byte)0x1);

                            // light up flag RA
                            sendOriginalData[m_RA_BYTE_OFFSET] = (byte) (sendOriginalData[m_RA_BYTE_OFFSET] | (byte) 0x80);
                            // light up flag AA
                            sendOriginalData[m_AA_BYTE_OFFSET] = (byte) (sendOriginalData[m_AA_BYTE_OFFSET] & (byte) 0xFB);
                            System.out.println("lit up RA and unset AA");

                            DatagramPacket queryPacket = new DatagramPacket(sendOriginalData, sendOriginalData.length, clientIpAddress, clientPort);
                            serverSocket.send(queryPacket);
                            System.out.println("sending answer");

                        }else {
                            System.out.println("shit");
                        }

                        break;
                    }
                } else {
                    // TODO Debugging Purposes
                    System.out.println(1);
                }
            }

        }
    }


    /**
     * this mthods gets 2 bytes and get the short num they represent
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


}
