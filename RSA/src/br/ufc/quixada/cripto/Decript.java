package br.ufc.quixada.cripto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decript {

	 /**
	  * Decifra o bloco de dados e a chave cifrada usando a chave privada do destinatário.
	  * @param pvk A chave privada.
	  * @param textoCifrado Os dados cifrados.
	  * @param chaveCifrada A chave cifrada.
	  * @return Os dados decifrados.
	  * @throws NoSuchAlgorithmException Algoritmo AES não disponível na sua versão do JDK.
	  * @throws NoSuchPaddingException PKCS5Padding não disponível na sua versão do JDK.
	  * @throws InvalidKeyException Se a chave passada for inválida.
	  * @throws IllegalBlockSizeException Não deve ocorrer.
	  * @throws BadPaddingException Se houver um erro de decifração (chave incorreta ou texto
	  * cifrado incorreto, por exemplo)
	  * @throws InvalidAlgorithmParameterException Não deve ocorrer.
	  */
	 public byte[] decifra(PrivateKey pvk, byte[] textoCifrado,
	   byte[] chaveCifrada) throws NoSuchAlgorithmException,
	   NoSuchPaddingException, InvalidKeyException,
	   IllegalBlockSizeException, BadPaddingException,
	   InvalidAlgorithmParameterException {
	  byte[] textoDecifrado = null;

	  // -- A) Decifrando a chave simétrica com a chave privada
	  Cipher rsacf = Cipher.getInstance("RSA");
	  rsacf.init(Cipher.DECRYPT_MODE, pvk);
	  byte[] chaveDecifrada = rsacf.doFinal(chaveCifrada);
	  // -- B) Decifrando o texto com a chave simétrica decifrada
	  Cipher aescf = Cipher.getInstance("AES/CBC/PKCS5Padding");
	  IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
	  aescf.init(Cipher.DECRYPT_MODE,
	    new SecretKeySpec(chaveDecifrada, "AES"), ivspec);
	  textoDecifrado = aescf.doFinal(textoCifrado);

	  return textoDecifrado;
	 }	
}
