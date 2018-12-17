package master;

import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.crypto.provider.SunJCE;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


 
public class AES {

	  public static String encrypt(String raw, String pass) throws Exception {
	      Cipher c = getCipher(Cipher.ENCRYPT_MODE, pass);

	      byte[] encryptedVal = c.doFinal(raw.getBytes("UTF-8"));
	      return new BASE64Encoder().encode(encryptedVal);
	  }

	  private static Cipher getCipher(int mode, String pass) throws Exception {
	      Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", new SunJCE());

	      //a random Init. Vector. just for testing
	      byte[] iv = "e675f725e675f725".getBytes("UTF-8");

	      c.init(mode, generateKey(pass), new IvParameterSpec(iv));
	      return c;
	  }

	  public static String decrypt(String encrypted, String pass) throws Exception {

	      byte[] decodedValue = new BASE64Decoder().decodeBuffer(encrypted);

	      Cipher c = getCipher(Cipher.DECRYPT_MODE, pass);
	      byte[] decValue = c.doFinal(decodedValue);

	      return new String(decValue);
	  }

	  private static Key generateKey(String pass) throws Exception {
	      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	      char[] password = pass.toCharArray();
	      byte[] salt = "S@1tS@1t".getBytes("UTF-8");

	      KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
	      SecretKey tmp = factory.generateSecret(spec);
	      byte[] encoded = tmp.getEncoded();
	      return new SecretKeySpec(encoded, "AES");

	  }
 
/*    private static SecretKeySpec secretKey;
    private static byte[] key;
 
    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
 
    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
 
    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }*/
}