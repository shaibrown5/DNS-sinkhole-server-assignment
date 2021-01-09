package il.ac.idc.cs.sinkhole;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.net.*;
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

    public static void main(String[] args) throws Exception
    {
        //buffer fo holding the incoming datagraצ
        byte[] receiveData = new byte[1024];
        // binds port 5300 to socket on local host
        DatagramSocket serverSocket = new DatagramSocket(5300);
        byte[] sendData;


        while(true)
        {
            // get random root server and get its IP
            String rootServer = getRandomRootServer();
            InetAddress ipAddress = InetAddress.getByName(rootServer);

            // create datagram packet
            DatagramPacket sendPacket = new DatagramPacket(receiveData, receiveData.length, ipAddress, 53);
            // creates packet to receive data of length receiveData.length
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            // halts until query received
            serverSocket.receive(receivePacket);
            System.out.println("recevied first packet");

            InetAddress add = receivePacket.getAddress();
            int curPort = receivePacket.getPort();
            sendPacket.setData(receivePacket.getData());
            // send the packet
            serverSocket.send(sendPacket);
            System.out.println("sent first response");

            for (int i = 0; i < 16 ; i++) {
                DatagramPacket responsePacket = new DatagramPacket(receiveData, receiveData.length);
                // halts until query received from authority
                serverSocket.receive(responsePacket);
                System.out.println("recevied packet " + i);
                int index = responsePacket.getOffset();
                System.out.println(index);

                //----------------------------------------------------------------------------------------------------------------------
                //this gives me the rep of each byte in hexa form
                //for debugging
                for (int j = 0; j < receivePacket.getLength(); j++) {
                    System.out.print((char)(receiveData[j]));
                }
                System.out.println("\n");
                for (int j = 0; j < receivePacket.getLength(); j++) {
                    System.out.print(" 0x" + String.format("%x", receiveData[j]) + " " );
                }
                System.out.println("\n");

                DataInputStream din = new DataInputStream(new ByteArrayInputStream(receiveData));
                int transactionNum = din.readShort(); // first 2 bytes as int
                int flagBytes = din.readShort(); //second 2 bytes (num the flags represent as int)
                boolean hasNoError = hasNoError(String.format("%x", flagBytes)); // boolean checking if there is no error
                System.out.println("is it error free? " + hasNoError);
                int numQuestion = din.readShort(); // third 2 bytes, # question
                int numAnswers = din.readShort(); // fourth 2 bytes # of answers
                int numAuthority = din.readShort(); // fifth 2 bytes # of authority
                int numAdditional = din.readShort();// sixth 2 bytes # of additional

                // skip the question part (ends in 0x0101)
                boolean inQuestion = true;
                StringBuilder endSectionChecker = new StringBuilder();
                while(inQuestion){
                    byte b = din.readByte();
                    int num = (b == 0 || b == 1) ? b : 9;
                    endSectionChecker.append(num);

                    if (endSectionChecker.toString().endsWith("0101")){
                        inQuestion = false;
                        endSectionChecker = new StringBuilder();
                    }
                }
                System.out.println("finished question section");



                byte b;
                StringBuilder s = new StringBuilder();
                boolean b1 = true;
                while (b1) {
                    try {
                        b = din.readByte();
                        int test = Byte.toUnsignedInt(b);
                        char c = test < 32 ? '.' : (char)(test);
                        System.out.print(c);
                        s.append(c);
                    } catch (EOFException e) {
                        b1 = false;
                    }
                }
                System.out.println(s.toString());




                if(hasNoError){
                    if(numAnswers == 0 && numAuthority >0){
                        // TODO ---------------------------
                        // get the next wanted address
                        byte c = din.readByte();
                        while (c < 32){
                            c = din.readByte();
                        }

                        String nextAddress ="";

                        while (c != -64){ //192 in unsigned
                            int test = Byte.toUnsignedInt(c);
                            char let = test < 32 ? '.' : (char)(test);
                            c = din.readByte();
                            nextAddress += let;
                        }
                        //remove the last character
                        nextAddress = nextAddress.substring(0,nextAddress.length()-1);
                        System.out.println("exiting authority with adress " + nextAddress);
                    }
                }
























            }
        }
    }

    /***
     * This method returns a random root servers Inet address
     * @return random Inet hostname
     */
    public static String getRandomRootServer(){
        // gets a letter from a - m
        char letter = (char) ((int) (Math.random() * ('m' - 'a'+ 1) + 'a'));

        return letter + ".root-servers.net";
    }

    /**
     * This method checks if the RCODE returns a no error response (last byte is 0)
     * @param hexNum: the hexadecimal representation of the flags header
     * @return true if there is a no error response, false otherwise.
     */
    private static boolean hasNoError(String hexNum){
        boolean ans = false;

        if(hexNum.endsWith("0")){
            ans = true;
        }

        return ans;
    }
}
