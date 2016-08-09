
import javacard.framework.APDU;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

//引入国密包

import com.guomi.*;

//文件系统定义
public class Test {


	byte [] TransPubKey;
	
	//国密定义
	public MessageDigest 	GM_MSD;
	public Signature       	GM_Signature;
	public Cipher        	GM_Cipher;
	public GMKeyPair	  	GM_KeyPair;
	public Cipher        	SM4_Cipher_ECB;
	public Cipher        	SM4_Cipher_CBC;
	public GMCipherExtend   cipherExtend;
	
	public SM2PublicKey    SM2pubkey1 = null;
	public SM2PrivateKey   SM2prikey1 = null;
	public SM2PublicKey    SM2pubkey2 = null;
	public SM2PrivateKey   SM2prikey2 = null;
	public SM2PublicKey    SM2pubkey3 = null;
	public SM2PrivateKey   SM2prikey3 = null;
	public SM2PublicKey    SM2pubkey4 = null;
	public SM2PrivateKey   SM2prikey4 = null;
	public SM2PublicKey    SM2pubkey5 = null;
	public SM2PrivateKey   SM2prikey5 = null;
	
	public SM4Key		   GM_SM4key1 = null;
	public SM4Key		   GM_SM4key2 = null;
	public SM4Key		   GM_SM4key3 = null;
	public SM4Key		   GM_SM4key4 = null ;
	public SM4Key		   GM_SM4key5 = null;
	
	public byte [] ZA;
	
	public byte [] SM4_INPUT_FLAG;
	
	//签名缓存区，头两字节定义为缓存偏移
	public byte [] Sign_buf;
	
	public byte Update_Flag = 0;

	
	public Test(ObjectSource ObjSRC)
	{
		super();
    	
		//存放公钥数组,存放格式为（1）byte索引+（64）byte公钥
		TransPubKey = new byte[65*5];

		ZA = JCSystem.makeTransientByteArray((short)0x20, JCSystem.CLEAR_ON_RESET);
		
		SM4_INPUT_FLAG = new byte [5];
		//国密
		SM2pubkey1 = (SM2PublicKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2prikey1 = (SM2PrivateKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2pubkey2 = (SM2PublicKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2prikey2 = (SM2PrivateKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2pubkey3 = (SM2PublicKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2prikey3 = (SM2PrivateKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2pubkey4 = (SM2PublicKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2prikey4 = (SM2PrivateKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2pubkey5 = (SM2PublicKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		SM2prikey5 = (SM2PrivateKey)GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256, true);
		GM_KeyPair = new GMKeyPair(GMKeyPair.ALG_SM2_FP,GMKeyBuilder.LENGTH_SM2_FP_256);
    	
		GM_SM4key1 = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4, GMKeyBuilder.LENGTH_SM4, false);
		GM_SM4key2 = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4, GMKeyBuilder.LENGTH_SM4, false);
		GM_SM4key3 = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4, GMKeyBuilder.LENGTH_SM4, false);
		GM_SM4key4 = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4, GMKeyBuilder.LENGTH_SM4, false);
		GM_SM4key5 = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4, GMKeyBuilder.LENGTH_SM4, false);
		
		GM_Signature = GMSignature.getInstance(GMSignature.ALG_SM2_SM3_256, false);
		GM_Cipher = GMCipher.getInstance(GMCipher.ALG_SM2_WITH_SM3_NOPAD, false);
		
		GM_MSD = GMMessageDigest.getInstance(GMMessageDigest.ALG_SM3_256, false);
	
		SM4_Cipher_ECB = GMCipher.getInstance(GMCipher.ALG_SM4_ECB_NOPAD, false);
		SM4_Cipher_CBC = GMCipher.getInstance(GMCipher.ALG_SM4_CBC_NOPAD, false);
		
		Sign_buf = new byte [2048];
		Util.setShort(Sign_buf, (short)0, (short)0x02);
		
	}

	//交易公钥验签、加密
	public void Public_Key_Cal(APDU apdu)throws CardRuntimeException
	{

		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0xFF);
		short resultlen = 0;
		
		if(cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(p1<1&&p1>0x05)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		//加密
		if((p2&0x01) == 0x01)
		{
			switch(p1){
			case 01:
				GM_Cipher.init(SM2pubkey1, Cipher.MODE_ENCRYPT);
				break;
			case 02:
				GM_Cipher.init(SM2pubkey2, Cipher.MODE_ENCRYPT);
				break;
			case 03:
				GM_Cipher.init(SM2pubkey3, Cipher.MODE_ENCRYPT);
				break;
			case 04:
				GM_Cipher.init(SM2pubkey4, Cipher.MODE_ENCRYPT);
				break;
			case 05:
				GM_Cipher.init(SM2pubkey5, Cipher.MODE_ENCRYPT);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
			resultlen  = GM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short)(lc&0x00FF), buf, ISO7816.OFFSET_CDATA);
		}
		//验签
//		else
//		{
//			
//			switch(p1){
//				case 01:	
//					GM_Signature.init(SM2pubkey1, GM_Signature.MODE_VERIFY);
//					break;
//				case 02:
//					GM_Signature.init(SM2pubkey2, GM_Signature.MODE_VERIFY);
//					break;
//				case 03:
//					GM_Signature.init(SM2pubkey3, GM_Signature.MODE_VERIFY);
//					break;
//				case 04:
//					GM_Signature.init(SM2pubkey4, GM_Signature.MODE_VERIFY);
//					break;
//				case 05:
//					GM_Signature.init(SM2pubkey5, GM_Signature.MODE_VERIFY);
//
//					break;
//				default:
//					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
//			}
//			//update
//			if((p2&0x80) == 0x00)
//			{
//				if(GM_Signature!= null)
//					GM_Signature.update(buf, ISO7816.OFFSET_CDATA, lc);
//			}
//			else
//			{
//				Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, (short)(ISO7816.OFFSET_CDATA+32), lc);
//				Util.arrayCopyNonAtomic(ZA, (short)0, buf, ISO7816.OFFSET_CDATA, (short)32);
//				if(GM_Signature!= null)
//					resultlen = GM_Signature.verify(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
//				//ZA加签名的明文 + 签名结果
//			}
//			
//		}

		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)resultlen);
		
		return;

	}
	//交易私钥签名
	public void Private_Key_Sign(APDU apdu)throws CardRuntimeException
	{
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0x00FF);
		short resultlen = 0;
		short offset = 0;
		short len = 0;
		
		if(cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(p1<1&&p1>0x05)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		//解密
		if((p2&0x01) == 0x01)
		{
			switch(p1){
			case 01:
				GM_Cipher.init(SM2prikey1, Cipher.MODE_DECRYPT);
				break;
			case 02:
				GM_Cipher.init(SM2prikey2, Cipher.MODE_DECRYPT);
				break;
			case 03:
				GM_Cipher.init(SM2prikey3, Cipher.MODE_DECRYPT);
				break;
			case 04:
				GM_Cipher.init(SM2prikey4, Cipher.MODE_DECRYPT);
				break;
			case 05:
				GM_Cipher.init(SM2prikey5, Cipher.MODE_DECRYPT);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
			resultlen  = GM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short)lc, buf, ISO7816.OFFSET_CDATA);
		}
		//签名
		else
		{
			
			switch(p1){
				case 01:	
					GM_Signature.init(SM2prikey1, GM_Signature.MODE_SIGN);
					break;
				case 02:
					GM_Signature.init(SM2prikey2, GM_Signature.MODE_SIGN);
					break;
				case 03:
					GM_Signature.init(SM2prikey3, GM_Signature.MODE_SIGN);
					break;
				case 04:
					GM_Signature.init(SM2prikey4, GM_Signature.MODE_SIGN);
					break;
				case 05:
					GM_Signature.init(SM2prikey5, GM_Signature.MODE_SIGN);

					break;
				default:
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
			
	
			//update
//			if((p2&0x80) == 0x00)
//			{
//				getZa(p1);
//				Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, (short)(ISO7816.OFFSET_CDATA+32), lc);
//				Util.arrayCopyNonAtomic(ZA, (short)0, buf, ISO7816.OFFSET_CDATA, (short)32);
//				GM_Signature.update(buf, ISO7816.OFFSET_CDATA, (short)(lc+32));
//				return;
//			}
//			//sign
//			else
//			{
//
//				if(GM_Signature!= null){
//					resultlen = GM_Signature.sign(buf,ISO7816.OFFSET_CDATA, (short)(lc+32), buf, ISO7816.OFFSET_CDATA);
//					Util.arrayFillNonAtomic(ZA, (short)0, (short)32, (byte)0);
//				}
//
//			}
			offset = getOffset();
			//update
			if((p2&0x80) == 0x00)
			{
				 if(offset == 0x02)
					 offset+=32;
				 Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, Sign_buf, offset, lc);
				 Util.setShort(Sign_buf, (short)0, (short)(offset+lc));
				 Update_Flag|=0x01;
//				 Util.arrayCopyNonAtomic(Sign_buf,(short)2, buf, ISO7816.OFFSET_CDATA, (short)0x80);
//				 apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)0x80);
				 return;
			}
			//sign
			else
			{
				getZa(p1);
				if(Update_Flag == 0x01)
				{
					Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, Sign_buf, offset, lc);
					offset+=lc;
					Util.arrayCopyNonAtomic(ZA, (short)0, Sign_buf, (short)2,(short)32);
					len = (short)(offset-2);

				}
				else
				{
					Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, (short)(ISO7816.OFFSET_CDATA+32), lc);
					Util.arrayCopyNonAtomic(ZA, (short)0, buf, ISO7816.OFFSET_CDATA, (short)32);
					len = (short)(lc+32);
				}
				if(GM_Signature!= null&&Update_Flag == 0x01)
				{
					resultlen = GM_Signature.sign(Sign_buf,(short)2,len, buf, ISO7816.OFFSET_CDATA);
					Update_Flag = 0;
					Util.arrayFillNonAtomic(Sign_buf, (short)2, (short)(Sign_buf.length-2), (byte)0);
					Util.setShort(Sign_buf, (short)0, (short)0x02);
				}
				else
				{
					if(GM_Signature!= null){
						resultlen = GM_Signature.sign(buf,ISO7816.OFFSET_CDATA, (short)(lc+32), buf, ISO7816.OFFSET_CDATA);
					}
				}
		}

		}
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)resultlen);
		return;
		

	}
	
	public void READ_PUBKEY(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short len = 0;
		short offset = 0;
		
		if(cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(p1>0x05&&p1<1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(p2 != 0x00)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		Find_Pub_byIndex(buf,p1);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)0x40);
		return;
	}


	//导入SM4密钥
	public void IMPORT_SM4_KEY(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0x00FF);
		short reslen = 0;
		
		if(cla != 0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(Cur_LifeStyle != (byte)0xFF)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		if(lc != 0x10 )
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if(p2 !=0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		if(p1>0x05&&p1<1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);


		if(ChenckIndex(p1))
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(p1 == 0x01){
			GM_SM4key1.setKey(buf, ISO7816.OFFSET_CDATA);
			GM_SM4key1.getKey(buf, (short)(ISO7816.OFFSET_CDATA+16));
			SM4_INPUT_FLAG[0] = 0x01;
		}
		else if(p1 == 0x02){
			GM_SM4key2.setKey(buf, ISO7816.OFFSET_CDATA);
			SM4_INPUT_FLAG[1] = 0x01;
		}
		else if(p1 == 0x03){
			GM_SM4key3.setKey(buf, ISO7816.OFFSET_CDATA);
			SM4_INPUT_FLAG[2] = 0x01;
		}
		else if(p1 == 0x04){
			GM_SM4key4.setKey(buf, ISO7816.OFFSET_CDATA);
			SM4_INPUT_FLAG[3] = 0x01;
		}
		else if(p1 == 0x05){
			GM_SM4key5.setKey(buf, ISO7816.OFFSET_CDATA);
			SM4_INPUT_FLAG[4] = 0x01;
		}

		return;
		
	}
	
	//产生SM2密钥对
	public void GEN_SM2_KEYPAIR(APDU apdu)throws CardRuntimeException
	{
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		//short lc = 0;
		short reslen = 0;
		
		if(cla != 0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(Cur_LifeStyle != (byte)0xFF)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		if(p2 !=0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		if(p1>0x05&&p1<1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		
		//检索对应索引的密钥是否已存在
		if(TransPubKey[(p1-1)*65] == p1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		//保存密钥索引
		buf[ISO7816.OFFSET_LC] = p1;
		
		if(p1 == 0x01){
			GM_KeyPair.genSM2KeyPair();
			SM2prikey1 = (SM2PrivateKey) GM_KeyPair.getPrivate();
			SM2pubkey1 = (SM2PublicKey) GM_KeyPair.getPublic();
			reslen = SM2pubkey1.getW(buf, ISO7816.OFFSET_CDATA);
			reslen = SM2prikey1.getS(buf, (short)(ISO7816.OFFSET_CDATA+0x40));
		}
		else if(p1 == 0x02){
			GM_KeyPair.genSM2KeyPair();
			SM2prikey2 = (SM2PrivateKey) GM_KeyPair.getPrivate();
			SM2pubkey2 = (SM2PublicKey) GM_KeyPair.getPublic();
			reslen = SM2pubkey1.getW(buf, ISO7816.OFFSET_CDATA);
		}
		else if(p1 == 0x03){
			GM_KeyPair.genSM2KeyPair();
			SM2prikey3 = (SM2PrivateKey) GM_KeyPair.getPrivate();
			SM2pubkey3 = (SM2PublicKey) GM_KeyPair.getPublic();
			reslen = SM2pubkey1.getW(buf, ISO7816.OFFSET_CDATA);
		}
		else if(p1 == 0x04){
			GM_KeyPair.genSM2KeyPair();
			SM2prikey4 = (SM2PrivateKey) GM_KeyPair.getPrivate();
			SM2pubkey4 = (SM2PublicKey) GM_KeyPair.getPublic();
			reslen = SM2pubkey1.getW(buf, ISO7816.OFFSET_CDATA);
		}
		else if(p1 == 0x05){
			GM_KeyPair.genSM2KeyPair();
			SM2prikey5 = (SM2PrivateKey) GM_KeyPair.getPrivate();
			SM2pubkey5 = (SM2PublicKey) GM_KeyPair.getPublic();
			reslen = SM2pubkey1.getW(buf, ISO7816.OFFSET_CDATA);
		}
		//拷贝公钥到存储区域
		Util.arrayCopy(buf, ISO7816.OFFSET_LC, TransPubKey, (short)((p1-1)*65), (short)(reslen+1));

		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)0x60);
		return;
	}
	
	//导入SM2密钥
	public void IMPORT_SM2_KEY(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte offset_pub = 0x05;
		byte offset_pri = 0x45;
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0xFF);
		short reslen = 0;
		
		if(cla != 0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(Cur_LifeStyle != (byte)0xFF)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		if(lc != 0x60 )
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if(p2 !=0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		if(p1>0x05&&p1<1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		//检索对应索引的密钥是否已存在
		if(TransPubKey[(p1-1)*65] == p1)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		//Save the key index
		buf[ISO7816.OFFSET_LC] = p1;
		
		if(p1 == 0x01){
			//Set the private and public key
			SM2prikey1.setS(buf, (short)offset_pri, (short)0x20);
			SM2pubkey1.setW(buf, (short)offset_pub, (short)0x40);

		}
		else if(p1 == 0x02){
			SM2prikey2.setS(buf, (short)offset_pri, (short)0x20);
			SM2pubkey2.setW(buf, (short)offset_pub, (short)0x40);
		}
		else if(p1 == 0x03){
			SM2prikey3.setS(buf, (short)offset_pri, (short)0x20);
			SM2pubkey3.setW(buf, (short)offset_pub, (short)0x40);
		}
		else if(p1 == 0x04){
			SM2prikey4.setS(buf, (short)offset_pri, (short)0x20);
			SM2pubkey4.setW(buf, (short)offset_pub, (short)0x40);
		}
		else if(p1 == 0x05){
			SM2prikey5.setS(buf, (short)offset_pri, (short)0x20);
			SM2pubkey5.setW(buf, (short)offset_pub, (short)0x40);
		}
		//sava the public key
		Util.arrayCopy(buf, ISO7816.OFFSET_LC, TransPubKey, (short)((p1-1)*65), (short)65);

		return;
	}
	//检查对应的索引是否已存在
	public boolean ChenckIndex(byte index)
	{
		switch (index) {
		case 1:
			if(SM4_INPUT_FLAG[0] == 0x01)
				return true;
			break;
		case 2:
			if(SM4_INPUT_FLAG[1] == 0x01)
				return true;
			break;
		case 3:
			if(SM4_INPUT_FLAG[2] == 0x01)
				return true;
			break;
		case 4:
			if(SM4_INPUT_FLAG[3] == 0x01)
				return true;
			break;
		case 5:
			if(SM4_INPUT_FLAG[4] == 0x01)
				return true;
			break;
			
		}
		return false;
	}
	
	public void SM3_CAL(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();

		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0xFF);
		short reslen = 0;	
		if(cla != 0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(p1!=0x00||p2!=0x00)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		reslen = GM_MSD.doFinal(buf, ISO7816.OFFSET_CDATA, lc, buf, ISO7816.OFFSET_CDATA);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)reslen);
		return;
	}
	
	public void SM4_CAL(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (apdu.setIncomingAndReceive()&0xFF);
		short reslen = 0;
		byte index = (byte)(p1&0x07);
		byte [] IV = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		if(cla != 0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		if(index>5&&index<1)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		//ECB
		if(p2 == 0x00)
		{
			//加密
			if((p1&(byte)0x80) == 0x00)
			{
				switch (index) {
				case 1:
					SM4_Cipher_ECB.init(GM_SM4key1, Cipher.MODE_ENCRYPT);
					break;
				case 2:
					SM4_Cipher_ECB.init(GM_SM4key2, Cipher.MODE_ENCRYPT);
					break;
				case 3:
					SM4_Cipher_ECB.init(GM_SM4key3, Cipher.MODE_ENCRYPT);
					break;
				case 4:
					SM4_Cipher_ECB.init(GM_SM4key4, Cipher.MODE_ENCRYPT);
					break;
				case 5:
					SM4_Cipher_ECB.init(GM_SM4key5, Cipher.MODE_ENCRYPT);
					break;

				default:
					break;
				}
			}
			//解密
			else if((p1&(byte)0x80) == (byte)0x80)
			{
				switch (index) {
				case 1:
					SM4_Cipher_ECB.init(GM_SM4key1, Cipher.MODE_DECRYPT);
					break;
				case 2:
					SM4_Cipher_ECB.init(GM_SM4key2, Cipher.MODE_DECRYPT);
					break;
				case 3:
					SM4_Cipher_ECB.init(GM_SM4key3, Cipher.MODE_DECRYPT);
					break;
				case 4:
					SM4_Cipher_ECB.init(GM_SM4key4, Cipher.MODE_DECRYPT);
					break;
				case 5:
					SM4_Cipher_ECB.init(GM_SM4key5, Cipher.MODE_DECRYPT);
					break;

				default:
					break;
				}
			}
			reslen = SM4_Cipher_ECB.doFinal(buf, ISO7816.OFFSET_CDATA, lc, buf, ISO7816.OFFSET_CDATA);
		}
		//CBC
		else if(p2 == 0x01)
		{

			//加密
			if((p1&(byte)0x80) == 0x00)
			{
				switch (index) {
				case 1:
					SM4_Cipher_CBC.init(GM_SM4key1, Cipher.MODE_ENCRYPT, IV, (short)0, (short)16);
					break;
				case 2:
					SM4_Cipher_CBC.init(GM_SM4key2, Cipher.MODE_ENCRYPT, IV, (short)0, (short)16);
					break;
				case 3:
					SM4_Cipher_CBC.init(GM_SM4key3, Cipher.MODE_ENCRYPT, IV, (short)0, (short)16);
					break;
				case 4:
					SM4_Cipher_CBC.init(GM_SM4key4, Cipher.MODE_ENCRYPT, IV, (short)0, (short)16);
					break;
				case 5:
					SM4_Cipher_CBC.init(GM_SM4key5, Cipher.MODE_ENCRYPT, IV, (short)0, (short)16);
					break;

				default:
					break;
				}
			}
			//解密
			else if((p1&(byte)0x80) == (byte)0x80)
			{
				switch (index) {
				case 1:
					SM4_Cipher_CBC.init(GM_SM4key1, Cipher.MODE_DECRYPT, IV, (short)0, (short)16);
					break;
				case 2:
					SM4_Cipher_CBC.init(GM_SM4key2, Cipher.MODE_DECRYPT, IV, (short)0, (short)16);
					break;
				case 3:
					SM4_Cipher_CBC.init(GM_SM4key3, Cipher.MODE_DECRYPT, IV, (short)0, (short)16);
					break;
				case 4:
					SM4_Cipher_CBC.init(GM_SM4key4, Cipher.MODE_DECRYPT, IV, (short)0, (short)16);
					break;
				case 5:
					SM4_Cipher_CBC.init(GM_SM4key5, Cipher.MODE_DECRYPT, IV, (short)0, (short)16);
					break;

				default:
					break;
				}
			}
			reslen = SM4_Cipher_CBC.doFinal(buf, ISO7816.OFFSET_CDATA, lc, buf, ISO7816.OFFSET_CDATA);
		
		}
		
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)reslen);
		return;
	}
	
	public void getZa(byte p1)
	{
		byte [] ID = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
		if(p1 == 0x01){
			cipherExtend.getZa(ID, (short)0, (short)16, SM2pubkey1, ZA, (short)0, cipherExtend.PARAM_FP_256);
		}
		else if(p1 == 0x02)
		{
			cipherExtend.getZa(ID, (short)0, (short)16, SM2pubkey2, ZA, (short)0, cipherExtend.PARAM_FP_256);
		}
		else if(p1 == 0x03)
		{
			cipherExtend.getZa(ID, (short)0, (short)16, SM2pubkey3, ZA, (short)0, cipherExtend.PARAM_FP_256);
		}
		else if(p1 == 0x04)
		{
			cipherExtend.getZa(ID, (short)0, (short)16, SM2pubkey4, ZA, (short)0, cipherExtend.PARAM_FP_256);
		}
		else if(p1 == 0x05)
		{
			cipherExtend.getZa(ID, (short)0, (short)16, SM2pubkey5, ZA, (short)0, cipherExtend.PARAM_FP_256);
		}
		
	}
	
	public void Find_Pub_byIndex(byte [] buf,byte index)
	{
		Util.arrayCopyNonAtomic(TransPubKey, (short)((index-1)*65+1), buf, (short)5, (short)0x40);
	}
	
	public short getOffset()
	{
		return Util.getShort(Sign_buf, (short)0);
	}
	
}
