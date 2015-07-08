/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ferdianto.simplechat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 * @author ferdhie
 */
public class Telnet implements Runnable {
    
    Socket socket;
    public Telnet(Socket socket) {
        this.socket=socket;
    }

    @Override
    public void run() {
        BufferedReader br = null;
        String hostname=null;
        try {
            InetSocketAddress address = (InetSocketAddress) socket.getRemoteSocketAddress();
            hostname = address.getAddress().getHostAddress();
            System.err.println("Connection from host " + hostname);
            
            br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String s=null;
            while(null!=(s=br.readLine())) {
                System.err.println(hostname + " " + s);
                Thread.yield();
            }
        } catch (IOException ex) {
            System.err.println(hostname + " error " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            if(br!=null) {
                try{br.close();} catch(Exception ex){}
            }
            if(socket!=null) {
                try{socket.close();} catch(Exception ex){}
            }
        }
    }
    
    public static void main(String[] args) throws IOException {
        ServerSocket server = null;
        try {
            server = new ServerSocket(23);
            while(true) {
                    Socket client = server.accept();
                    Telnet telnet = new Telnet( client );
                    Thread thread = new Thread(telnet);
                    thread.setDaemon(true);
                    thread.start();
                Thread.yield();
            }
        } finally {
            if (server!=null)
                try { server.close(); } catch(Exception ex){}
        }
    }
    
}
