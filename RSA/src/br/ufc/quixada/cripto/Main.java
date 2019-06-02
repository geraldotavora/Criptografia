package br.ufc.quixada.cripto;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import br.ufc.quixada.cripto.GeradorChave;

public class Main {

	public static void main(String[] args) throws Exception{
		 // -- Gera o par de chaves, em dois arquivos (chave.publica e
		  // chave.privada)
		  GeradorChave gerador = new GeradorChave();
		  gerador.geraParChaves(new File("chave.publica"), new File("chave.privada"));

		  // -- Cifrando a mensagem "Hello, world!"
		  
		  
		  byte[] textoClaro = "Hello, world!".getBytes("ISO-8859-1");
		  PublicKey pub = gerador.LerChavePublica(new File("chave.publica"));
		  Enc cf = new Enc();
		  byte[][] encriptado = cf.cifra(pub, textoClaro);
//		  printHex(encriptado[0]);
//		  printHex(encriptado[1]);

		  // -- Decifrando a mensagem
		  PrivateKey pvk = gerador.LerChavePriv(new File("chave.privada"));
		  Decript decripta = new Decript();
		  byte[] decifrado = decripta.decifra(pvk, encriptado[0], encriptado[1]);
		  
		  System.out.println ("Texto claro: \n"+new String (textoClaro, "ISO-8859-1"));
		  
		  System.out.println("\nTexto cifrado: ");
		  for(int i=0; i < decifrado.length; i++) {
		  System.out.print(decifrado[i]);
		  }
		  
		  System.out.println("\n\nTexto decifrado:");
		  System.out.println (new String(decifrado, "ISO-8859-1"));
//		  printHex(decifrado);
		 }	
}
