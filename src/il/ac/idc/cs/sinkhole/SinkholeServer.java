package il.ac.idc.cs.sinkhole;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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

            //----------------------------------------------------------------------------------------------------------------------
            for (int i = 0; i < receivePacket.getLength(); i++) {
                System.out.print(" 0x" + String.format("%x", receiveData[i]) + " " );
            }
            System.out.println("\n");


            DataInputStream din = new DataInputStream(new ByteArrayInputStream(receiveData));
            int transactionNum = Integer.parseInt(String.valueOf(din.readShort()),16); // first 2 bytes
            // need to check flags for Rcode (errors) which are the last 4 bytes = | QR1 | Opcode4 | AA1 | TC1 | RD1 | RA1| Z3 | RCODE4 |
            // so need to rethink this. this gives me the int value need to check this and use string.format
            int flags = Integer.parseInt(String.valueOf(din.readShort()),16); //second 2 bytes
            int numQuestion = Integer.parseInt(String.valueOf(din.readShort()),16); // third 2 bytes, # question
            int numAnswers = Integer.parseInt(String.valueOf(din.readShort()),16); // fourth 2 bytes # of answers
            int numAuthority = Integer.parseInt(String.valueOf(din.readShort()),16); // fifth 2 bytes # of authority
            int numAdditional = Integer.parseInt(String.valueOf(din.readShort()),16);// sixth 2 bytes # of additional
            // System.out.println("Additional RRs: 0x" + String.format("%x", din.readShort()));---------------------------------------------


            InetAddress add = receivePacket.getAddress();
            int curPort = receivePacket.getPort();
            sendPacket.setData(receivePacket.getData());

            // send the packet
            serverSocket.send(sendPacket);

            for (int i = 0; i < 16 ; i++) {
                DatagramPacket responsePacket = new DatagramPacket(receiveData, receiveData.length);
                // halts until query received from authority
                serverSocket.receive(responsePacket);


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

    //sketch for getting and reading the authority stuff by tal
//    public static int respectMyAuthoritah(int DNSMessage) {
//        int temp = DNSMessage << (4 + 4); // id + flags
//        int qSize = temp >> (32 - 4 - 4 - 4); // to get Question value
//        int qLen;// get the length of Question with str.length() + WRAPPER
//        temp = temp << 4; // id + flags+ quest
//        int ansRRSize = temp >> (32 - (4 * 4)); // to get answ value
//        int ansRRlen; // get the length of Question with str.length() + WRAPPER
//        temp = temp << 4; // id + flags+ quest + ansRR
//        int autRRSize = temp >> (32 - (4 * 5)); // to get Auth value
//        int autRRlen; // get the length of Question with str.length() + WRAPPER
//        temp = temp << 4; // id + flags+ quest + ansRR + auth
//        int addRRSize = temp >> (32 - (4 * 6)); // to get Additional value
//        int addRRlen; // get the length of Question with str.length() + WRAPPER
//        temp = DNSMessage << (4 * 6 + qLen + ansRRlen);
//        return temp >> (4 * 6 + qLen + ansRRlen + addRRlen);
//    }


}
