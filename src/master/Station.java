package master;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import org.apache.axis2.context.MessageContext;
import org.apache.commons.codec.digest.Crypt;

/*
 * TODO:
 * 	diseñar capa de seguridad y adaptar
 * 		establecimiento de sesion
 * 		RSA autentificacion con firmado, generacion de claves AESS, generacion de claves RSA
 * 		tokens de sesion (con timeout)
 * 		acceso por niveles
 * decodificar UMLs!!!!!
 */

public class Station {

	class User {
		public String hashedUsername;
		public String salt;
		public String hashedPass;
		// admin or user
		public String permissions;

		public User(String hashedUsername, String salt, String hashedPass, String permissions) {
			this.hashedUsername = hashedUsername;
			this.salt = salt;
			this.hashedPass = hashedPass;
			this.permissions = permissions;
		}
		
		@Override
		public String toString() {
			try {
				return URLEncoder.encode(hashedUsername, "UTF-8")
					+"\t"+URLEncoder.encode(salt, "UTF-8")
					+"\t"+URLEncoder.encode(hashedPass, "UTF-8")
					+"\t"+URLEncoder.encode(permissions, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				return "";
			}
		}
	}

	private Map<String, String> sessions = new HashMap<String, String>();
	private Map<String, User> users = new HashMap<String, User>();

	private File station = new File(System.getProperty("user.dir")
			+ System.getProperty("file.separator") + "Station.txt");
	private File log = new File(System.getProperty("user.dir")
			+ System.getProperty("file.separator") + "logs"
			+ System.getProperty("file.separator") + "log.txt");
	private File userDB = new File(System.getProperty("user.dir")
			+ System.getProperty("file.separator") + "users.db");
	private File sessionDB = new File(System.getProperty("user.dir")
			+ System.getProperty("file.separator") + "session.db");
	private File encryption_key = new File(System.getProperty("user.dir")
			+ System.getProperty("file.separator") + ".key");
	
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
	
	private String key;

	private User getUser(String token) {
		return users.get(digest(sessions.get(token)));
	}
	
	public String cypher (String s) {
		try {	
			if (seguridad)
				return AES.encrypt(s, key);
			else
				return s;
		} catch (Exception e) {
			System.err.println("Error!!");
			System.err.println(e);
			return "Internal error";
		}
	}
	
	public String decypher (String s) {
		try {
			if (seguridad)
				return AES.decrypt(s, key);
			else
				return s;
		} catch (Exception e) {
			System.err.println("Error!!");
			System.err.println(e);
			return "Internal error";
		}
	}
	
	private String getToken() {
		//a-z A-Z 0-9
		String token = "";
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[10];
		random.nextBytes(bytes);
		for(int i=0; i<10; i++) {
			int result = ((bytes[i]<0?-1:1) * (int) bytes[i]) % 62;
			if (result < 26) {
				token += (char) ('a'+result);
			} else if (result < 52) {
				token += (char) ('A'+result-26);
			} else {
				token += (char) ('0'+result-52);
			}
		}
		return token;
	}

	private String digest(String s, String salt) {
		String pepper = "5m89";
		return Crypt.crypt(s, "$6$"+salt + pepper);
	}
	
	private String digest(String s) {
		return digest(s, "63dj01kvga");
	}

	public String newUser(String token_C, String username_C, String password_C, String permissions_C) {
		String token = decypher(token_C);
		String username = decypher(username_C);
		String password = decypher(password_C);
		String permissions = decypher(permissions_C);
		if(!sessions.containsKey(token) || !getUser(token).permissions.equals("admin")) {
			return cypher("Access denied");
		} else {
			String salt = getToken();
			String hashedPass = digest(password, salt);
			String hashedUsername = digest(username);
	
			String action = "09#createUser#";
			try {
				writeLog(action + URLEncoder.encode(username, "UTF-8") + "#" + URLEncoder.encode(permissions, "UTF-8"), token);
				if(!permissions.equals("user") && !permissions.equals("admin")) {
					return cypher("Wrong value");
				}
				actualizarUsuarios();
				if(users.containsKey(hashedUsername)) {
					return cypher("Taken username");
				}
				User user = new User(hashedUsername, salt, hashedPass, permissions);
				escribirUsuario(user);
				users.put(hashedUsername, user);
				return cypher("OK");
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + username + "#" + permissions, token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

	private boolean authenticateUser(String username, String password) {
		try {
			User user = users.get(digest(username));
			return digest(password, user.salt).equals(user.hashedPass);
		} catch (NullPointerException e) {
			return false;
		}
	}
	
	private void actualizarSesiones() throws IOException {
		if(sessionDB.exists()) {
			FileReader in = new FileReader(sessionDB);
			BufferedReader br = new BufferedReader(in);

			String temp;
			String out = "";
			while ((temp = br.readLine()) != null) {
				out += temp + "\n";
			}
			String[] tokens = out.split("\n");
			String[] values;
			// gets the sessions
			for (int i = 0; i < tokens.length; i++) {
				values = tokens[i].split("\t");
				if (values.length==2) {
					sessions.put(values[0], values[1]);
				}
			}

			br.close();
			
			reescribirSesiones();
		}
	}
	
	//Reescribe los usuarios para eliminar aquellos erroneos ignorados en la lectura.
	private void reescribirSesiones() throws IOException {
		if (!sessionDB.exists() || sessionDB.delete()) {
			for(String token : sessions.keySet()) {
				escribirSesion(token, sessions.get(token));
			}
		} else {
			throw new IOException("Unable to delete the file \"" + sessionDB
					+ "\"");
		}
	}

	private void escribirSesion(String token, String username) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(sessionDB,
				true))) {
			writer.println(token+"\t"+username);
		} catch (FileNotFoundException e) {
			throw new IOException(e);
		}
	}

	private void actualizarUsuarios() throws IOException {
		if(userDB.exists()) {
			FileReader in = new FileReader(userDB);
			BufferedReader br = new BufferedReader(in);

			String temp;
			String out = "";
			while ((temp = br.readLine()) != null) {
				out += temp + "\n";
			}
			String[] tokens = out.split("\n");
			String[] values;
			// gets the users
			for (int i = 0; i < tokens.length; i++) {
				values = tokens[i].split("\t");
				if (values.length==4) {
					if (values[3].equals("admin") || values[3].equals("user"))
						users.put(URLDecoder.decode(values[0], "UTF-8"),
								new User(URLDecoder.decode(values[0], "UTF-8"),
										 URLDecoder.decode(values[1], "UTF-8"),
										 URLDecoder.decode(values[2], "UTF-8"),
										 URLDecoder.decode(values[3], "UTF-8")));
				}
			}

			br.close();
			
			reescribirUsuarios();
		}
	}
	
	//Reescribe los usuarios para eliminar aquellos erroneos ignorados en la lectura.
	private void reescribirUsuarios() throws IOException {
		if (userDB.delete()) {
			for(User user : users.values()) {
				escribirUsuario(user);
			}
		} else {
			throw new IOException("Unable to delete the file \"" + userDB
					+ "\"");
		}
	}

	private void escribirUsuario(User user) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(userDB,
				true))) {
			writer.println(user);
		} catch (FileNotFoundException e) {
			throw new IOException(e);
		}
	}

	public Station() {
		try {
			if (station.createNewFile()) {
				escribir();
			} else {
				actualizar();
			}
			File folder = (new File(System.getProperty("user.dir")
					+ System.getProperty("file.separator") + "logs"));
			if (!folder.exists() || !folder.isDirectory()) {
				if (!folder.mkdirs()) {
					throw new IOException(
							"Unable to create the folder \"logs\"");
				}
			}

			log.createNewFile();
			
			actualizarUsuarios();
			
			if(encryption_key.exists() && encryption_key.isDirectory()) {
				throw new IOException("Unable to create key");
			} else if (encryption_key.exists()) {
				try (BufferedReader br = new BufferedReader(new FileReader(userDB))) {
					key = br.readLine();
				}
			} else {
				key = "Remind yourself that overconfidence is a slow and insidious killer";
				try (PrintWriter writer = new PrintWriter(new FileOutputStream(encryption_key,
						true))) {
					writer.println(key);
				} catch (FileNotFoundException e) {
					throw new IOException(e);
				}
			}

		} catch (IOException e) {
			System.err.println("Error while creating file!");
			System.err.println(e);
		}

	}

	
	//If token==null, user is guest!!!!!
	private String logInfo(String action, String token) {
		String logLine = "";
		// Gets the UTC time
		SimpleDateFormat date = new SimpleDateFormat("HH:mm:ss dd/MM/yyyy");
		date.setTimeZone(TimeZone.getTimeZone("UTC"));
		logLine += date.format(new Date()) + "\t";
		// Gets the ip
		MessageContext inMessageContext = MessageContext
				.getCurrentMessageContext();
		logLine += (String) inMessageContext.getProperty("REMOTE_ADDR") + "\t";
		// Gets the user
		logLine += (token==null?"":sessions.get(token))+"\t";
		// Gets the operation
		logLine += action;
		return logLine;
	}

	private void writeLog(String action, String token) throws IOException {
		String logLine = logInfo(action, token);
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(log,
				true))) {
			writer.println(logLine);
		} catch (FileNotFoundException e) {
			throw new IOException(e);
		}
	}

	private void actualizar() throws IOException {
		FileReader in = new FileReader(station);
		BufferedReader br = new BufferedReader(in);

		String temp;
		String out = "";
		while ((temp = br.readLine()) != null) {
			out += temp + "\n";
		}

		String[] tokens = out.split("\n");
		temperatura = Integer.parseInt(tokens[0].substring(12));
		humedad = Integer.parseInt(tokens[1].substring(8));
		luminosidad = Integer.parseInt(tokens[2].substring(12));
		seguridad = Boolean.parseBoolean(tokens[3].substring(10));
		pantalla = tokens[4].substring(9);
		// In case the pantalla string has \n chars in it
		for (int i = 5; i < tokens.length; i++) {
			pantalla += "\n" + tokens[i];
		}

		br.close();
	}

	private void escribir() throws IOException {
		if (station.delete()) {
			BufferedWriter writer = new BufferedWriter(new FileWriter(
					station.toString()));
			writer.write("Temperatura=" + temperatura + "\r\n" + "Humedad="
					+ humedad + "\r\n" + "Luminosidad=" + luminosidad + "\r\n"
					+ "Seguridad=" + seguridad + "\r\n" + "Pantalla="
					+ pantalla);
			writer.close();
		} else {
			throw new IOException("Unable to delete the file \"" + station
					+ "\"");
		}
	}
	
	public String newConnection(String username_C, String password_C) {
		String username = decypher(username_C);
		String password = decypher(password_C);
		
		String action = "00#signIn#"+username;
		String token = digest(getToken());
		
		try {
			writeLog(action, null);
			
			actualizarUsuarios();
			
			if(!authenticateUser(username, password)) {
				return cypher("Wrong value");
			} else {
				sessions.put(token, username);
				reescribirSesiones();
				System.out.println(token);
				return cypher("OK\n"+token);
			}
			
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(logInfo(action, null));
			System.err.println(e);
			return cypher("Internal error");
		}
	}
	
	public String closeConnection(String token_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "10#signOut#"+sessions.get(token);
			try {
				writeLog(action, token);
				sessions.remove(token);
				reescribirSesiones();
				return cypher("OK");
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action, null));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}
	
	public String getTemperatura(String token_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "01#getTemperatura#";
			try {
				actualizar();
				String value = Integer.toString(temperatura);
				writeLog(action + value, token);
				return cypher("OK\n"+value);
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???", token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

	public String getHumedad(String token_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "02#getHumedad#";
			try {
				actualizar();
				String value = Integer.toString(humedad);
				writeLog(action + value, token);
				return cypher("OK\n"+value);
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???", token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

	public String getLuminosidad(String token_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "03#getLuminosidad#";
			try {
				actualizar();
				String value = Integer.toString(luminosidad);
				writeLog(action + value, token);
				return cypher("OK\n"+value);
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???", token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

	public String getPantalla(String token_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "04#getPantalla#";
			try {
				actualizar();
				writeLog(action + URLEncoder.encode(pantalla, "UTF-8"), token);
				return cypher("OK\n"+pantalla);
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???", token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

	public String setTemperatura(String token_C, String temperatura_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "05#setTemperatura#";
			try {
				actualizar();
				writeLog(action + this.temperatura + "#" + decypher(temperatura_C), token);
				
				int temperatura = Integer.parseInt(decypher(temperatura_C));
				if (MIN_temperatura <= temperatura
						&& temperatura <= MAX_temperatura) {
					this.temperatura = temperatura;
					escribir();
					return cypher("OK");
				} else {
					return cypher("Wrong value");
				}
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???#" + decypher(temperatura_C), token));
				System.err.println(e);
				return cypher("Internal error");
			} catch (NumberFormatException e) {
				return cypher("Wrong value");
			}
		}
	}

	public String setHumedad(String token_C, String humedad_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "06#setHumedad#";
			try {
				actualizar();
				writeLog(action + this.humedad + "#" + decypher(humedad_C), token);
				
				int humedad = Integer.parseInt(decypher(humedad_C));
				if (MIN_humedad <= humedad && humedad <= MAX_humedad) {
					this.humedad = humedad;
					escribir();
					return cypher("OK");
				} else {
					return cypher("Wrong value");
				}
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???#" + decypher(humedad_C), token));
				System.err.println(e);
				return cypher("Internal error");
			} catch (NumberFormatException e) {
				return cypher("Wrong value");
			}
		}
	}

	public String setLuminosidad(String token_C, String luminosidad_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "07#setLuminosidad#";
			try {
				actualizar();
				writeLog(action + this.luminosidad + "#" + decypher(luminosidad_C), token);
				
				int luminosidad = Integer.parseInt(decypher(luminosidad_C));
				if (MIN_luminosidad <= luminosidad
						&& luminosidad <= MAX_luminosidad) {
					this.luminosidad = luminosidad;
					escribir();
					return cypher("OK");
				} else {
					return cypher("Wrong value");
				}
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???#" + decypher(luminosidad_C), token));
				System.err.println(e);
				return cypher("Internal error");
			} catch (NumberFormatException e) {
				return cypher("Wrong value");
			}
		}
	}

	public String setPantalla(String token_C, String pantalla_C) {
		try {
			actualizarSesiones();
		} catch (IOException e) {
			System.err.println("Error!!");
			System.err.println(e);
			return cypher("Internal error");
		}
		String token = decypher(token_C);
		String pantalla = decypher(pantalla_C);
		if(!sessions.containsKey(token)) {
			return cypher("Access denied");
		} else {
			String action = "08#setPantalla#";
			try {
				actualizar();
				writeLog(action + URLEncoder.encode(this.pantalla, "UTF-8") + "#"
						+ URLEncoder.encode(pantalla, "UTF-8"), token);
				this.pantalla = pantalla;
				escribir();
				return cypher("OK");
			} catch (IOException e) {
				System.err.println("Error!!");
				System.err.println(logInfo(action + "???#" + decypher(pantalla_C), token));
				System.err.println(e);
				return cypher("Internal error");
			}
		}
	}

}