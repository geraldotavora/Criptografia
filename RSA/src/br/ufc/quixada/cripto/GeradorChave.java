package br.ufc.quixada.cripto;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;

public class GeradorChave {

		 private static final int RSAKEYSIZE = 1024;

		 /**
		  * Gera um par de chaves e as guarda em formato serializado em arquivos.
		  * @param fPub O arquivo que irá conter a chave pública.
		  * @param fPvk O arquivo que irá conter a chave privada.
		  * @throws IOException Problemas de acesso/gravação do arquivo.
		  * @throws NoSuchAlgorithmException RSA não disponível nesta versão do JDK.
		  * @throws InvalidAlgorithmParameterException Não deve ocorrer.
		  * @throws CertificateException Não deve ocorrer.
		  * @throws KeyStoreException Não deve ocorrer.
		  */
		 public void geraParChaves(File fPub, File fPvk) throws IOException,
		   NoSuchAlgorithmException, InvalidAlgorithmParameterException,
		   CertificateException, KeyStoreException {

		  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		  kpg.initialize(new RSAKeyGenParameterSpec(RSAKEYSIZE,
		    RSAKeyGenParameterSpec.F4));
		  KeyPair kpr = kpg.generateKeyPair();
		  PrivateKey priv = kpr.getPrivate();
		  PublicKey pub = kpr.getPublic();

		  // -- Gravando a chave pública em formato serializado
		  ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(
		    fPub));
		  oos.writeObject(pub);
		  oos.close();

		  // -- Gravando a chave privada em formato serializado
		  oos = new ObjectOutputStream(new FileOutputStream(fPvk));
		  oos.writeObject(priv);
		  oos.close();

		 }
		 
		 public PrivateKey LerChavePriv(File kpr) throws IOException,
		   ClassNotFoundException {
		  ObjectInputStream is = new ObjectInputStream(new FileInputStream(kpr));
		  PrivateKey ret = (PrivateKey) is.readObject();
		  is.close();
		  return ret;
		 }
		
		public PublicKey LerChavePublica( File kpu ) throws FileNotFoundException, IOException,
		ClassNotFoundException {
			ObjectInputStream is = new ObjectInputStream(new FileInputStream(kpu));
			PublicKey ret = (PublicKey)is.readObject();
			is.close();
			return ret;
		}
}
