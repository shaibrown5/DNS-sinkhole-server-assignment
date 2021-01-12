package il.ac.idc.cs.sinkhole;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
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
            System.out.println(rootServer);
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


//                DataInputStream din1 = new DataInputStream(new ByteArrayInputStream(receiveData));
//                byte m;
//                byte l;
//                boolean flag = true;
//                int count = 1;
//                while (flag) {
//                    try {
//                        m = din1.readByte();
//                        l= din1.readByte();
//
//                        int bi = Byte.toUnsignedInt(m);
//                        int li = Byte.toUnsignedInt(l);
//
//                        char c = bi < 32 ? '.' : (char)(bi);
//                        char c1 = li < 32 ? '.' : (char)(li);
//                        System.out.print(count + ":  " + c + "(" + bi + ")   " + c1 + "(" + li + ")\n");
//                        count ++;
//                    } catch (EOFException e) {
//                        flag = false;
//                    }
//                }

                DataInputStream din = new DataInputStream(new ByteArrayInputStream(receiveData));
                // handle, read and save all the headers total of 12 bytes or 6 shorts
                int transactionNum = din.readShort(); // first 2 bytes as int
                int flagBytes = din.readShort(); //second 2 bytes (num the flags represent as int)
                boolean hasNoError = hasNoError(String.format("%x", flagBytes)); // boolean checking if there is no error
                int numQuestion = din.readShort(); // third 2 bytes, # question
                int numAnswers = din.readShort(); // fourth 2 bytes # of answers
                int numAuthority = din.readShort(); // fifth 2 bytes # of authority
                int numAdditional = din.readShort();// sixth 2 bytes # of additional

                System.out.println("number of answers: " + numAnswers);
                System.out.println("number of authority: " + numAuthority);
                System.out.println("is it error free? " + hasNoError);

                if(hasNoError){
                    if(numAnswers == 0 && numAuthority >0){
                        // skip the question name part (ends in 0x0)
                        byte b = passSection(din);
                        // read and skip qtype and qclass = 2+2=4 bytes
                        b = passOverBytes(din, 4);

                        System.out.println("finished question section");


                        // get the next wanted address
                        // read the name part of authority
                        b = passSection(din);
                        System.out.println("finished reading name");
                        // read and pass over type, class, ttl, rdlenth = 1+2+4+2 = 9
                        // note that the first byte of type was already read
                        b = passOverBytes(din, 9);
                        System.out.println("finished reading type, class, ttl, rdlength");

                        // get address from Rdata
                        StringBuilder addressBuilder = new StringBuilder();
                        // reads the amount of letters to read
                        int numToRead = din.readByte();
                        // run until we finish getting the first address.
                        while(numToRead != 0){
                            for (int j = 0; j < numToRead ; j++) {
                                b = din.readByte();
                                addressBuilder.append((char)(b));
                            }
                            addressBuilder.append('.');

                            numToRead = din.readByte();
                        }

                        // remove the last .
                        String address = addressBuilder.substring(0, addressBuilder.length()-1);
                        System.out.println("finish reading address: " + address);
                        // TODO FOR SOMEREASON THE WRONG ADDRESS IS PRINTED WHEN RUNNING, IN DEBUG IT IS OK
                        System.out.println("shai");
                        break;
                    }
                }
            }
        }
    }

    /**
     * This method reads a certain ammount of bytes and returns the last byte read
     * @param din - the data input stream connected to the data
     * @param numBytesToRead - the ammount of bytes to read
     * @return the last byte read
     */
    public static byte passOverBytes(DataInputStream din, int numBytesToRead){
        byte b = 0;
        try{
            for (int i = 0; i < numBytesToRead; i++) {
                b = din.readByte();
            }
        }
        catch (EOFException eof){
            System.err.println("Passing bytes failed, stream finished");
        }
        catch (Exception e){
            System.err.println("Passing bytes failed, stream got an IO exception");
        }
        finally {
            return b;
        }
    }

    /**
     * This method passes through a section in the DNS packet by reading bytes until it reaches a zero byte
     * @param din: the data input stream attached to the data
     * @return the last byte read
     */
    public static byte passSection(DataInputStream din){
        byte b = 0;

        try {
            do{
                b = din.readByte();
            } while(b != 0);

        }
        catch (EOFException eof){
            System.err.println("Passing section failed, stream finished");
        }
        catch (Exception e){
            System.err.println("passing section failed, stream got an IO exception");
        }
        finally {
            return b;
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
