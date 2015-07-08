/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ferdianto.simplechat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.SecretKey;

/**
 *
 * @author ferdhie
 */
public class SimpleChatClient {
    static SecretKey serverSecret;
    
    static String encode(String plainText) throws Exception {
        SimpleChat.log("send ", plainText);
        byte[] plain = plainText.getBytes();
        byte[] encrypted = SimpleChat.encrypt(serverSecret, plain);
        String base64 = Base64.encode(encrypted);
        SimpleChat.log("send encoded", base64);
        return base64 + "\r\n";
    }
    
    public static void main(String[] args) throws IOException, Exception {
        serverSecret = SimpleChat.getSecretKey(SimpleChat.SERVER_KEY);
        Socket s = new Socket("localhost", SimpleChat.SERVER_PORT);
        
        new Thread() {
            private Socket socket;
            @Override
            public void run() {
                try {
                    BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String s=null;
                    while ( null != ( s = br.readLine() ) ) {
                        byte[] enc = Base64.decode(s);
                        try {
                            byte[] plain = SimpleChat.decrypt(serverSecret, enc);
                            String plainText = new String(plain);
                            SimpleChat.log("\nREPLY FROM SERVER: ", plainText);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                } catch (IOException ex) {
                    try {
                        socket.close();
                    } catch (Exception ex1) {
                    }
                }
                
            }
            public Thread set(Socket s) {
                this.socket=s;
                this.setDaemon(true);
                return this;
            }
        }.set(s).start();
        
        PrintWriter pw = new PrintWriter(new OutputStreamWriter( s.getOutputStream() ));
        pw.print(encode("LOGIN muklis ******"));
        pw.flush();
        
        pw.print(encode("PING"));
        pw.flush();
        
        pw.print(encode("LIST"));
        pw.flush();
        
        System.in.read();
        s.close();
        
    }
    
}
