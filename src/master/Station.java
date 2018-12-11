package master;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.rmi.RemoteException;

/*
 * TODO:
 * 	diseñar capa de seguridad y adaptar
 * 		generacion de logs
 * 		establecimiento de sesion
 * 		tokens de sesion y tickets
 * 		hasheado
 * 		user y pass
 * 	generacion automatica de archivo de texto
 */

public class Station {
    File station;
    
    final static int MIN_temperatura = -30;
    final static int MAX_temperatura = 50;
    
    final static int MIN_humedad = 0;
    final static int MAX_humedad = 100;
    
    final static int MIN_luminosidad = 0;
    final static int MAX_luminosidad = 800;
    
    int temperatura = 0;
    int humedad = 0;
    int luminosidad = 0;
    String pantalla = "";
    boolean seguridad = false;
    
    public Station(File file) {
        station = file;
        
    }
    
    private void actualizar() {
          try (FileReader in = new FileReader(station)) {
            BufferedReader br = new BufferedReader(in);
            
            String temp;
            String out = "";
            while ((temp = br.readLine()) != null) {
                out += temp+"\n";
            }
            
            String[] tokens = out.split("\n");
            temperatura = Integer.parseInt(tokens[0].substring(12));
            humedad = Integer.parseInt(tokens[1].substring(8));
            luminosidad = Integer.parseInt(tokens[2].substring(12));
            pantalla = tokens[3].substring(9);
            //In case the pantalla string has \n chars in it
            for(int i=4; i<tokens.length; i++) {
                pantalla += "\n"+tokens[i];
            }
        } catch (IOException e) {
            System.err.println("Error accesing the data:");
            System.err.println(e+"\n");
        }
    }
    
    private boolean escribir() {
        boolean out = true;
        if(station.delete()) {
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(station.toString()));) {
                
                writer.write(
                        "Temperatura="+temperatura+"\r\n" +
                        "Humedad="+humedad+"\r\n" +
                        "Luminosidad="+luminosidad+"\r\n" +
                        "Pantalla="+pantalla
                );
                writer.close();
                
            } catch (IOException e) {
                System.err.println("Error trying to change file:");
                System.err.println(e+"\n");
                out = false;
            }
        } else {
            out = false;
        }
        return out;
    }
    
    public String getTemperatura() {
        actualizar();
        return Integer.toString(temperatura);
    }
    
    public String getHumedad() {
        actualizar();
        return Integer.toString(humedad);
    }
    
    public String getLuminosidad() {
        actualizar();
        return Integer.toString(luminosidad);
    }
    
    public String getPantalla() {
        actualizar();
        return pantalla;
    }
    
    public String setTemperatura(int temperatura) {
        actualizar();
        this.temperatura = temperatura;
        if (escribir()) {
        	return "OK";
        } else {
        	return "NOT OK";
        }
    }
    
    public String setHumedad(int humedad) {
        actualizar();
        this.humedad = humedad;
        if(escribir()) {
        	return "OK";
        } else {
        	return "NOT OK";
        }
    }
    
    public String setLuminosidad(int luminosidad) {
        actualizar();
        this.luminosidad = luminosidad;
        if (escribir()) {
        	return "OK";
        } else {
        	return "NOT OK";
        }
    }
    
    public String setPantalla(String pantalla) {
        actualizar();
        this.pantalla = pantalla;
        if (escribir()) {
        	return "OK";
        } else {
        	return "NOT OK";
        }
    }

}