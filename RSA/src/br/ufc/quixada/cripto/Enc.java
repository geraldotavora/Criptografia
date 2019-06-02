package br.ufc.quixada.cripto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Enc {

	
	 /**
	  * Cifra um bloco de dados com a chave pública.
	  *
	  * @param pub
	  *            A chave pública.
	  * @param textoClaro
	  *            O bloco de dados a ser cifrado.
	  * @return Dois arrays de bytes, sendo que o primeiro é o bloco cifrado, e o
	  *         segundo é a chave gerada e cifrada. Não jogue fora nenhum deles.
	  * @throws NoSuchAlgorithmException
	  *             Algoritmo (AES) não disponível na sua versão do JDK.
	  * @throws NoSuchPaddingException
	  *             Padding (PKCS5Padding) não disponível na sua versão do JDK.
	  * @throws InvalidKeyException
	  *             Se a chave pública for inválida.
	  * @throws IllegalBlockSizeException
	  *             Não deve ocorrer.
	  * @throws BadPaddingException
	  *             Não deve ocorrer.
	  * @throws InvalidAlgorithmParameterException
	  *             Não deve ocorrer.
	  */
	 public byte[][] cifra(PublicKey pub, byte[] textoClaro)
	   throws NoSuchAlgorithmException, NoSuchPaddingException,
	   InvalidKeyException, IllegalBlockSizeException,
	   BadPaddingException, InvalidAlgorithmParameterException {
	  byte[] textoCifrado = null;
	  byte[] chaveCifrada = null;

	  // -- A) Gerando uma chave simétrica de 128 bits
	  KeyGenerator kg = KeyGenerator.getInstance("AES");
	  kg.init(128);
	  SecretKey sk = kg.generateKey();
	  byte[] chave = sk.getEncoded();
	  // -- B) Cifrando o texto com a chave simétrica gerada
	  Cipher aescf = Cipher.getInstance("AES/CBC/PKCS5Padding");
	  IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
	  aescf.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"),
	      ivspec);
	  textoCifrado = aescf.doFinal(textoClaro);
	  // -- C) Cifrando a chave com a chave pública
	  Cipher rsacf = Cipher.getInstance("RSA");
	  rsacf.init(Cipher.ENCRYPT_MODE, pub);
	  chaveCifrada = rsacf.doFinal(chave);

	  return new byte[][] { textoCifrado, chaveCifrada };
	 }
	
	
}
