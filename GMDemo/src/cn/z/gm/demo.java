package cn.z.gm;

import com.guomi.GMCipher;
import com.guomi.GMCipherExtend;
import com.guomi.GMKeyBuilder;
import com.guomi.GMKeyPair;
import com.guomi.GMSM2KeyExchange;
import com.guomi.GMSignature;
import com.guomi.SM2PrivateKey;
import com.guomi.SM2PublicKey;
import com.guomi.SM4Key;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class demo extends Applet {

	private GM gmInstance = null;

	public GMKeyPair dGM_KeyPair = null;
	public SM2PublicKey dSM2pubkey = null;
	public SM2PrivateKey dSM2prikey = null;
	public GMSM2KeyExchange dSM2KeyEx = null;
	public SM4Key dSM4key = null;

	public Cipher dGM_Cipher = null;
	public Signature dGM_Signature = null;
	public Cipher dSM4GM_Cipher_ECB = null;
	public Cipher dSM4GM_Cipher_CBC = null;

	// 导入的SM2key
	public SM2PublicKey dSM2pubkey1 = null;
	public SM2PrivateKey dSM2prikey1 = null;

	public final byte[] DEFAULT_SM4KEY = new byte[] { 0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
			0x4f };

	private final short SM4KEY_LENGTH = (short) 0x10;

	public final byte[] debugdata_SM4 = new byte[] { 0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
			0x4f };

	public final byte[] debugdata = new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
	public final byte[] debugdata_cipher = new byte[] { 0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
			0x4f };
	private final static byte[] ID = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
			0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	private final static byte [] IV = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	private byte[] ZA;

	demo() {
		gmInstance = new GM();

		dGM_KeyPair = new GMKeyPair(GMKeyPair.ALG_SM2_FP,
				GMKeyBuilder.LENGTH_SM2_FP_256);
		dSM2pubkey = (SM2PublicKey) GMKeyBuilder.buildKey(
				GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256,
				true);
		dSM2prikey = (SM2PrivateKey) GMKeyBuilder.buildKey(
				GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256,
				true);
		dSM2pubkey1 = (SM2PublicKey) GMKeyBuilder.buildKey(
				GMKeyBuilder.TYPE_SM2_PUBLIC, GMKeyBuilder.LENGTH_SM2_FP_256,
				true);
		dSM2prikey1 = (SM2PrivateKey) GMKeyBuilder.buildKey(
				GMKeyBuilder.TYPE_SM2_PRIVATE, GMKeyBuilder.LENGTH_SM2_FP_256,
				true);
		dSM4key = (SM4Key) GMKeyBuilder.buildKey(GMKeyBuilder.TYPE_SM4,
				GMKeyBuilder.LENGTH_SM4, false);
		dSM2KeyEx = GMSM2KeyExchange.getInstance();

		dGM_Cipher = GMCipher.getInstance(GMCipher.ALG_SM2_WITH_SM3_NOPAD,
				false);
		dGM_Signature = GMSignature.getInstance(GMSignature.ALG_SM2_SM3_256,
				false);
		dSM4GM_Cipher_ECB = GMCipher.getInstance(GMCipher.ALG_SM4_ECB_NOPAD,
				false);
		dSM4GM_Cipher_CBC = GMCipher.getInstance(GMCipher.ALG_SM4_CBC_NOPAD,
				false);

		ZA = JCSystem.makeTransientByteArray((short) 0x20,
				JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short reslen = 0;
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0xB1:
			gmInstance.GEN_SM2_KEYPAIR(apdu);
			break;
		case (byte) 0xB2:
			gmInstance.READ_PUBKEY(apdu);
			break;

		case (byte) 0xA1:// SM2密钥读取
			if (0x00 == p1) {
				// generate keypair
				dGM_KeyPair.genSM2KeyPair();
				dSM2prikey = (SM2PrivateKey) dGM_KeyPair.getPrivate();
				dSM2pubkey = (SM2PublicKey) dGM_KeyPair.getPublic();
			} else if (0x01 == p1) {
				// read public key
				switch (p2) {
				case (byte) 0x01:
					reslen = dSM2pubkey.getW(buf, (short) 0);
					break;
				case (byte) 0x02:
					reslen = dSM2pubkey.getA(buf, (short) 0);
					break;
				case (byte) 0x03:
					reslen = dSM2pubkey.getB(buf, (short) 0);
					break;
				case (byte) 0x04:
					reslen = dSM2pubkey.getG(buf, (short) 0);
					break;
				case (byte) 0x05:
					buf[0] = dSM2pubkey.getType();
					reslen = (short) 1;
					break;
				case (byte) 0x06:
					reslen = dSM2pubkey.getSize();
					buf[0] = (byte) ((short) (reslen >> 8) & (short) 0x00FF);
					buf[1] = (byte) (reslen & (short) 0x00FF);
					reslen = (short) 2;
					break;
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x02 == p1) {
				// read private key
				switch (p2) {
				case (byte) 0x01:
					reslen = dSM2prikey.getS(buf, (short) 0);// 获取SM2私钥数据，32
																// bytes;
					break;
				case (byte) 0x02:
					reslen = dSM2prikey.getA(buf, (short) 0);
					break;
				case (byte) 0x03:
					reslen = dSM2prikey.getB(buf, (short) 0);
					break;
				case (byte) 0x04:
					reslen = dSM2prikey.getG(buf, (short) 0);
					break;
				case (byte) 0x05:
					buf[0] = dSM2prikey.getType();
					reslen = (short) 1;
					break;
				case (byte) 0x06:
					reslen = dSM2prikey.getSize();
					buf[0] = (byte) ((short) (reslen >> 8) & (short) 0x00FF);
					buf[1] = (byte) (reslen & (short) 0x00FF);
					reslen = (short) 2;
					break;
				default:
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					break;
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x03 == p1) {// 读取GMCipherExtend信息
				switch (p2) {
				case (byte) 0x01:
					dSM2KeyEx.getParam(buf, (short) 0,
							GMSM2KeyExchange.PARAM_OTHER_TEMP_PUBLICKEY);
					break;
				default:
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					break;
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte) 0xA2:// SM2加解密签名验签
			if (0x00 == p1) {// 默认数据
				if (0x01 == p2) {// 公钥加密
					dGM_Cipher.init(dSM2pubkey, Cipher.MODE_ENCRYPT);
					reslen = dGM_Cipher.doFinal(debugdata, (short) 0,
							(short) debugdata.length, buf, (short) 0);
					apdu.setOutgoingAndSend((short) 0, reslen);
				} else if (0x02 == p2) {// 私钥签名
					dGM_Signature.init(dSM2prikey, dGM_Signature.MODE_SIGN);
					reslen = dGM_Signature.sign(debugdata, (short) 0,
							(short) (debugdata.length), buf, (short) 0);
					apdu.setOutgoingAndSend((short) 0, reslen);
				} else if (0x03 == p2) {// 私钥解密
					reslen = apdu.setIncomingAndReceive();
					dGM_Cipher.init(dSM2prikey, Cipher.MODE_DECRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
					apdu.setOutgoingAndSend((short) 0, reslen);
				} else if (0x04 == p2) {// 公钥验签
					reslen = apdu.setIncomingAndReceive();
					dGM_Signature.init(dSM2pubkey, dGM_Signature.MODE_VERIFY);
					if (!dGM_Signature.verify(debugdata, (short) 0,
							(short) (debugdata.length), buf,
							ISO7816.OFFSET_CDATA, reslen)) {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
			} else if (0x01 == p1) {// 指令数据加密签名
				reslen = apdu.setIncomingAndReceive();
				if (0x01 == p2) {// 公钥
					dGM_Cipher.init(dSM2pubkey, Cipher.MODE_ENCRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else if (0x02 == p2) {// 私钥
					dGM_Cipher.init(dSM2prikey, Cipher.MODE_ENCRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x02 == p1) {// 指令数据解密验签
				reslen = apdu.setIncomingAndReceive();
				if (0x01 == p2) {// 公钥
					dGM_Cipher.init(dSM2pubkey, Cipher.MODE_DECRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else if (0x02 == p2) {// 私钥
					dGM_Cipher.init(dSM2prikey, Cipher.MODE_DECRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte) 0xA3:// 导入SM2公私玥对，并用其加解密、签名验签。
			if (0x00 == p1) {// 写入SM2公私玥对
				reslen = apdu.setIncomingAndReceive();
				if (0x01 == p2) {// 写入公钥
					dSM2pubkey1.setW(buf, ISO7816.OFFSET_CDATA, (short) 0x40);
				} else if (0x02 == p2) {// 写入获取私钥
					dSM2prikey1.setS(buf, ISO7816.OFFSET_CDATA, (short) 0x20);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
			} else if (0x01 == p1) {// 指令数据加密、签名
				reslen = apdu.setIncomingAndReceive();
				if (0x01 == p2) {// 公钥加密
					dGM_Cipher.init(dSM2pubkey1, Cipher.MODE_ENCRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else if (0x02 == p2) {// 私钥签名，没有用户ID参与
					dGM_Signature.init(dSM2prikey1, dGM_Signature.MODE_SIGN);
					reslen = dGM_Signature.sign(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
				} else if (0x03 == p2) {// 私钥签名,用户ID为默认值.
					short sourcedataoff = (short) (ISO7816.OFFSET_CDATA + 1);
					byte sourcedatalen = buf[ISO7816.OFFSET_CDATA];
					GMCipherExtend.getZa(ID, (short) 0, (short) ID.length,
							dSM2pubkey1, ZA, (short) 0,
							GMCipherExtend.PARAM_FP_256);
					Util.arrayCopy(buf, sourcedataoff, buf, (short) ZA.length,
							(short) sourcedatalen);
					Util.arrayCopy(ZA, (short) 0, buf, (short) 0,
							(short) ZA.length);
					dGM_Signature.init(dSM2prikey1, dGM_Signature.MODE_SIGN);
					reslen = dGM_Signature
							.sign(buf, (short) 0,
									(short) (ZA.length + sourcedatalen), buf,
									(short) 0);
				} else if (0x04 == p2) {// 私钥签名,用户ID在指令数据中,userID(LV)+SourceData(LV)。
					short useridoff = (short) (ISO7816.OFFSET_CDATA + 1);
					byte useridlen = buf[ISO7816.OFFSET_CDATA];

					short sourcedataoff = (short) (useridoff + useridlen + 1);
					byte sourcedatalen = buf[ISO7816.OFFSET_CDATA + useridlen
							+ 1];
					GMCipherExtend.getZa(buf, useridoff, (short) useridlen,
							dSM2pubkey1, ZA, (short) 0,
							GMCipherExtend.PARAM_FP_256);
					Util.arrayCopy(buf, sourcedataoff, buf, (short) ZA.length,
							(short) sourcedatalen);
					Util.arrayCopy(ZA, (short) 0, buf, (short) 0,
							(short) ZA.length);
					dGM_Signature.init(dSM2prikey1, dGM_Signature.MODE_SIGN);
					reslen = dGM_Signature
							.sign(buf, (short) 0,
									(short) (ZA.length + sourcedatalen), buf,
									(short) 0);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x02 == p1) {// 指令数据解密、验签
				reslen = apdu.setIncomingAndReceive();
				if (0x01 == p2) {// 公钥验签，SourceData(LV)+Signature(LV)
					dGM_Signature.init(dSM2pubkey1, dGM_Signature.MODE_VERIFY);
					if (!dGM_Signature
							.verify(buf,
									(short) (ISO7816.OFFSET_CDATA + 1),
									buf[ISO7816.OFFSET_CDATA],
									buf,
									(short) (ISO7816.OFFSET_CDATA + 1
											+ buf[ISO7816.OFFSET_CDATA] + 1),
									buf[(short) (ISO7816.OFFSET_CDATA + 1 + buf[ISO7816.OFFSET_CDATA])])) {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else if (0x02 == p2) {// 私钥解密
					dGM_Cipher.init(dSM2prikey1, Cipher.MODE_DECRYPT);
					reslen = dGM_Cipher.doFinal(buf, ISO7816.OFFSET_CDATA,
							reslen, buf, (short) 0);
					apdu.setOutgoingAndSend((short) 0, reslen);
				} else if (0x03 == p2) {// 公钥验签,用户ID为默认值,SourceData(LV)+Signature(LV)。
					short sourcedataoff = (short) (ISO7816.OFFSET_CDATA + 1);
					byte sourcedatalen = buf[sourcedataoff - 1];

					short signatureoff = (short) (sourcedataoff + sourcedatalen + 1);
					byte signaturelen = buf[signatureoff - 1];

					GMCipherExtend.getZa(ID, (short) 0, (short) ID.length,
							dSM2pubkey1, ZA, (short) 0,
							GMCipherExtend.PARAM_FP_256);
					Util.arrayCopy(buf, sourcedataoff, buf, (short) ZA.length,
							(short) (sourcedatalen + 1 + signaturelen));
					Util.arrayCopy(ZA, (short) 0, buf, (short) 0,
							(short) ZA.length);
					dGM_Signature.init(dSM2pubkey1, dGM_Signature.MODE_VERIFY);
					if (!dGM_Signature.verify(buf, (short) 0,
							(short) (ZA.length + sourcedatalen), buf,
							(short) (ZA.length + sourcedatalen + 1),
							signaturelen)) {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else if (0x04 == p2) {// 公钥验签,用户ID在指令中,userid(LV)+SourceData(LV)+Signature(LV)。
					short useridoff = (short) (ISO7816.OFFSET_CDATA + 1);
					byte useridlen = buf[useridoff - 1];

					short sourcedataoff = (short) (useridoff + useridlen + 1);
					byte sourcedatalen = buf[sourcedataoff - 1];

					short signatureoff = (short) (sourcedataoff + sourcedatalen + 1);
					byte signaturelen = buf[signatureoff - 1];

					GMCipherExtend.getZa(buf, useridoff, (short) useridlen,
							dSM2pubkey1, ZA, (short) 0,
							GMCipherExtend.PARAM_FP_256);
					// ZA+sourcedata+signaturelen+signature
					Util.arrayCopy(buf, sourcedataoff, buf, (short) ZA.length,
							(short) (signatureoff + 1 + signaturelen));
					Util.arrayCopy(ZA, (short) 0, buf, (short) 0,
							(short) ZA.length);

					dGM_Signature.init(dSM2pubkey1, dGM_Signature.MODE_VERIFY);
					if (!dGM_Signature.verify(buf, (short) 0,
							(short) (ZA.length + sourcedatalen), buf,
							(short) (ZA.length + sourcedatalen + 1),
							signaturelen)) {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
			} else if (0x03 == p1) {// 读取密钥参数
				// 01~06：read private key；
				// 11~16：read public key
				switch (p2) {
				case (byte) 0x01:
					reslen = dSM2prikey1.getS(buf, (short) 0);
					break;
				case (byte) 0x02:
					reslen = dSM2prikey1.getA(buf, (short) 0);
					break;
				case (byte) 0x03:
					reslen = dSM2prikey1.getB(buf, (short) 0);
					break;
				case (byte) 0x04:
					reslen = dSM2prikey1.getG(buf, (short) 0);
					break;
				case (byte) 0x05:
					buf[0] = dSM2prikey1.getType();
					reslen = (short) 1;
					break;
				case (byte) 0x06:
					reslen = dSM2prikey1.getSize();
					buf[0] = (byte) ((short) (reslen >> 8) & (short) 0x00FF);
					buf[1] = (byte) (reslen & (short) 0x00FF);
					reslen = (short) 2;
					break;
				// read public key
				case (byte) 0x11:
					reslen = dSM2pubkey1.getW(buf, (short) 0);
					break;
				case (byte) 0x12:
					reslen = dSM2pubkey1.getA(buf, (short) 0);
					break;
				case (byte) 0x13:
					reslen = dSM2pubkey1.getB(buf, (short) 0);
					break;
				case (byte) 0x14:
					reslen = dSM2pubkey1.getG(buf, (short) 0);
					break;
				case (byte) 0x15:
					buf[0] = dSM2pubkey1.getType();
					reslen = (short) 1;
					break;
				case (byte) 0x16:
					reslen = dSM2pubkey1.getSize();
					buf[0] = (byte) ((short) (reslen >> 8) & (short) 0x00FF);
					buf[1] = (byte) (reslen & (short) 0x00FF);
					reslen = (short) 2;
					break;
				default:
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
					break;
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte) 0xA5:// SM4
			if (0x00 == p1) {// 读写SM4 key
				if (0x00 == p2) {// 写入SM4 key,默认密钥
					dSM4key.clearKey();
					dSM4key.setKey(DEFAULT_SM4KEY, (short) 0);
				} else if (0x01 == p2) {// 写入SM4 key,指令参数
					reslen = apdu.setIncomingAndReceive();
					if (reslen != SM4KEY_LENGTH) {
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					} else {
						dSM4key.clearKey();
						dSM4key.setKey(buf, ISO7816.OFFSET_CDATA);
					}
				} else if (0x02 == p2) {// 读取SM4 key
					reslen = (short) dSM4key.getKey(buf, (short) 0);
					apdu.setOutgoingAndSend((short) 0, reslen);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
			} else if (0x01 == p1) {// CBC加密
				dSM4GM_Cipher_CBC.init(dSM4key, Cipher.MODE_ENCRYPT,IV, (short)0, (short)16);
				if (0x00 == p2) {// 默认数据加密
					reslen = dSM4GM_Cipher_CBC.doFinal(debugdata_SM4,
							(short) 0, (short) debugdata_SM4.length, buf,
							(short) 0);
				} else if (0x01 == p2) {// 指令数据加密,必须填充0x00为16字节整数倍。
					reslen = apdu.setIncomingAndReceive();
					short filllen = (short) ((16 - (reslen & 0x000F)) & 0x000F);
					if ((short) 0 != filllen) {
						Util.arrayFillNonAtomic(buf,
								(short) (ISO7816.OFFSET_CDATA + reslen),
								filllen, (byte) 0x00);
					}
					reslen += filllen;
					reslen = dSM4GM_Cipher_CBC.doFinal(buf,
							ISO7816.OFFSET_CDATA, reslen, buf, (short) 0);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x02 == p1) {// CBC解密
				dSM4GM_Cipher_CBC.init(dSM4key, Cipher.MODE_DECRYPT,IV, (short)0, (short)16);
				if (0x01 == p2) {// 指令数据解密
					reslen = apdu.setIncomingAndReceive();
					if ((short) 0 == (short) (reslen & 0x0F)) {
						reslen = dSM4GM_Cipher_CBC.doFinal(buf,
								ISO7816.OFFSET_CDATA, reslen, buf, (short) 0);
					} else {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x03 == p1) {// ECB加密
				dSM4GM_Cipher_ECB.init(dSM4key, Cipher.MODE_ENCRYPT);
				if (0x00 == p2) {// 默认数据加密
					reslen = dSM4GM_Cipher_CBC.doFinal(debugdata_SM4,
							(short) 0, (short) debugdata_SM4.length, buf,
							(short) 0);
				} else if (0x01 == p2) {// 指令数据加密
					reslen = apdu.setIncomingAndReceive();
					short filllen = (short) ((16 - (reslen & 0x000F)) & 0x000F);
					if ((short) 0 != filllen) {
						Util.arrayFillNonAtomic(buf,
								(short) (ISO7816.OFFSET_CDATA + reslen),
								filllen, (byte) 0x00);
					}
					reslen += filllen;
					reslen = dSM4GM_Cipher_ECB.doFinal(buf,
							ISO7816.OFFSET_CDATA, reslen, buf, (short) 0);
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else if (0x04 == p1) {// ECB解密
				dSM4GM_Cipher_ECB.init(dSM4key, Cipher.MODE_DECRYPT);
				if (0x01 == p2) {// 指令数据解密
					reslen = apdu.setIncomingAndReceive();
					if ((short) 0 == (short) (reslen & 0x0F)) {
						reslen = dSM4GM_Cipher_ECB.doFinal(buf,
								ISO7816.OFFSET_CDATA, reslen, buf, (short) 0);
					} else {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, reslen);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}

			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
