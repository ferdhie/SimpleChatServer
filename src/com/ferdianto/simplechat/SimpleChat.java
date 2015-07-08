/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ferdianto.simplechat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ferdhie
 */
public class SimpleChat implements Runnable {
    static final int SERVER_PORT = 24281;
    static final String SERVER_KEY = "bismillah";
    static SecretKey serverSecret = null;
    static ConcurrentHashMap<String,SimpleChat> onlineUsers = new ConcurrentHashMap();
    
    String username=null;
    Socket socket = null;
    String hostname = null;

    public SimpleChat(Socket socket) {
        this.socket=socket;
    }
    
    @Override
    public void run() {
        try {
            doServer();
        } catch (Exception e) {
            try { socket.close(); } catch (Exception e2) {}
            log("exception: ", e.getMessage());
        } finally {
            logout();
        }
    }
    
    private void logout() {
        if (username!=null) {
            onlineUsers.remove(username);
            username=null;
        }
    }
    
    private void doServer() throws Exception {
        InetSocketAddress address = (InetSocketAddress) socket.getRemoteSocketAddress();
        hostname = address.getAddress().getHostAddress();
        log("Connection from host " + hostname);
        
        outThread.setDaemon(true);
        outThread.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String s;
        while( null != ( s = reader.readLine() ) ) {
            log("incoming message ", s);
            
            byte[] incoming = Base64.decode(s);
            log("base64 decoded ", hex(incoming));
            
            byte[] plaintext = decrypt( serverSecret, incoming );
            String plain = new String(plaintext);
            log("decrypted ", plain);
            
            handleMessage(plain);
        }
       
    }
    
    public static byte[] encrypt(SecretKey key, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new SecureRandom().generateSeed(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted =c.doFinal(plain);
        
        //add iv into the message
        byte[] encrypted_with_iv = new byte[ encrypted.length+16 ];
        System.arraycopy(iv, 0, encrypted_with_iv, 0, iv.length);
        System.arraycopy(encrypted, 0, encrypted_with_iv, 16, encrypted.length);
        
        return encrypted_with_iv;
    }
    
    public static byte[] decrypt(SecretKey key, byte[] encrypted) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(encrypted, 0, iv, 0, iv.length);

        byte[] msg = new byte[encrypted.length-16];
        System.arraycopy(encrypted, 16, msg, 0, msg.length);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        c.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plain = c.doFinal(msg);
        return plain;
    }
    
    public void respond(String msg) throws Exception {
        
        log("outgoing message ", msg);
        byte[] plaintext = msg.getBytes();
        
        byte[] encrypted = encrypt(serverSecret, plaintext);
        log("encrypted message ", hex(encrypted));
        
        String base64 = Base64.encode(encrypted);
        log("base64 out message ", base64);
        
        base64 = base64.replace("\n", "").replace("\r", "");
        base64 = base64 + "\r\n";
        
        outQueue.add(base64);
        
    }

    private void handleMessage(String s) throws Exception {
        String[] args = s.split(" ");
        String cmd = args[0];
        List<String> arguments = new ArrayList<String>();
        for(int i=1; i<args.length; i++) 
            arguments.add(args[i]);
        
        cmd = cmd.toUpperCase();
        
        if (cmd.equals("LOGIN")) {
            //register//login//online
            String uname = arguments.get(0);
            String pw = arguments.get(1);
            if (username!=null)
                onlineUsers.remove(username);
            username=uname;
            onlineUsers.put(username, this);
            respond("OK");
        } else if (cmd.equals("LOGOUT")) {
            //offline
            logout();
            respond("OK");
            throw new Exception("Done");
        } else if (cmd.equals("PING")) {
            //test server connection
            respond("PONG");
        } else if (cmd.equals("LIST")) {
            //list all online user
            if (username == null) {
                respond("ERROR not logged in");
            } else {

                StringBuilder sb = new StringBuilder("OK ");
                for(String u: onlineUsers.keySet()) {
                    sb.append("@").append(u).append(",");
                }
                if (sb.length()>0)
                    sb.setLength(sb.length()-1);
                respond(sb.toString());

            }   
        } else if (cmd.equals("MSG")) {
            //send message
            String to = arguments.get(0);
            StringBuilder sb = new StringBuilder("FROM ").append(username);
            for(int i=1; i<arguments.size(); i++) {
                sb.append(" ").append(arguments.get(i));
            }   if (username == null) {
                respond("ERROR not logged in");
            } else if (!onlineUsers.containsKey(to)) {
                respond("ERROR user " + to + "not online");
            } else {
                SimpleChat tujuan = onlineUsers.get(to);
                tujuan.respond(sb.toString());
            }   
        } else {
            respond("ERROR invalid command");
        }
        
    }
    
    private LinkedBlockingQueue<String> outQueue = new LinkedBlockingQueue(1000);
    private final Thread outThread = new Thread() {
        @Override
        public void run() {
            try {
                OutputStream out = socket.getOutputStream();
                while (true) {
                    String data = outQueue.take();
                    out.write(data.getBytes());
                    out.flush();
                    Thread.yield();
                }
            } catch (Exception e) {
                log("Outqueue died");
                outQueue.clear();
                try { socket.close(); } catch (Exception e2) {}
            }
        }
    };
    
    static SecretKey getSecretKey(String strKey) throws Exception {
        byte[] secret;
        try {
            secret = strKey.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            secret = strKey.getBytes();
        }
        
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] bkey = Arrays.copyOf(sha256.digest(secret), 128 / Byte.SIZE);
        SecretKey key = new SecretKeySpec(bkey, "AES");
        return key;
    }
    
    public static void main(String[] args) throws Exception {
        serverSecret = SimpleChat.getSecretKey(SERVER_KEY);
        ServerSocket ss = new ServerSocket(SERVER_PORT);
        log("server listen at " + ss.getInetAddress().getHostAddress() + ":" + SERVER_PORT);
        while (true) {
            Socket s = ss.accept();
            SimpleChat client = new SimpleChat(s);
            Thread thread = new Thread(client);
            thread.setDaemon(true);
            thread.start();
            Thread.yield();
        }
    }
    
    static void log(String... s) {
        StringBuilder sb = new StringBuilder();
        for(String str: s)
            sb.append(str).append(" ");
        sb.setLength(sb.length()-1);
        System.err.println( Thread.currentThread().getName() + " -- " + sb.toString() );
    }
    
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    static String hex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
