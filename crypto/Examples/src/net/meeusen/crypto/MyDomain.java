package net.meeusen.crypto;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Config;

public class MyDomain {



	/*
	 * Curve P-256
	p =	 115792089210356248762697446949407573530086143415290314195533631308867097853951
	r = 115792089210356248762697446949407573529996955224135760342422259061068512044369
	s =	 c49d3608 86e70493 6a6678e1 139d26b7 819f7e90
	c = 7efba166 2985be94 03cb055c 75d4f7e0 ce8d84a9 c5114abc af317768 0104fa0d
	b = 5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b
	Gx  = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
	Gy  = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5 
	 * */
	private String namedCurve;  
	private ECNamedCurveParameterSpec curveparams; 	
	int cofactor_h = 1; 
	ECCurve bccurve ;

	public MyDomain(String curvename) {
		this.namedCurve=curvename; 
		this.curveparams = ECNamedCurveTable.getParameterSpec(namedCurve);

	}

	public String getCurveName() {
		return namedCurve;
	}

	public BigInteger getPrime() {
		return curveparams.getCurve().getField().getCharacteristic(); 
	}

	public BigInteger getA() {
		return curveparams.getCurve().getA().toBigInteger();
	}

	public BigInteger getB() {
		return curveparams.getCurve().getB().toBigInteger();
	}

	public BigInteger getGx() {
		return curveparams.getG().getXCoord().toBigInteger();
	}

	public BigInteger getGy() {
		return curveparams.getG().getYCoord().toBigInteger();
	}

	public BigInteger getOrderN() {
		return curveparams.getN();
	}

	public java.security.spec.ECField getField() { 
		return new java.security.spec.ECFieldFp(getPrime()); 
	}

	public java.security.spec.EllipticCurve getCurve() {
		return new java.security.spec.EllipticCurve(getField(), getA(), getB()); 
	}

	public java.security.spec.ECParameterSpec getEcParamSpec() {
		return new java.security.spec.ECParameterSpec(getCurve(), getG(), getOrderN(), getCofactorH()) ;  // ECParameterSpec(EllipticCurve curve, ECPoint g, BigInteger n, int h)
	}

	public ECDomainParameters getBcParamSpec() {
		
		ECCurve.Fp bccurve = new ECCurve.Fp(this.getPrime(), this.getA(), this.getB() );
		org.bouncycastle.math.ec.ECPoint bc_g = bccurve.createPoint(this.getGx(),this.getGy());
		org.bouncycastle.crypto.params.ECDomainParameters domparams = new ECDomainParameters(bccurve, bc_g, this.getOrderN()); 
		return domparams;
		
	}
	
	public int getCofactorH() {
		return 1;
	}

	public java.security.spec.ECPoint getG() {
		return new java.security.spec.ECPoint(getGx(),getGy());
	}

	public static String bi2strh (BigInteger bi) {
		return new ByteString(bi.toByteArray()).toHexString() ;		
	}

	public String toString() {
		String nl="\n";
		return this.namedCurve + nl 
				+ "a-dec: " + getA()+ nl 
				+ "a-hex: " + bi2strh(getA())+ nl 
				+ "b-dec: " + getB()+ nl 
				+ "b-hex: " + bi2strh(getB())+ nl 
				+ "p-dec: " + getPrime()+ nl 
				+ "p-hex: " + bi2strh(getPrime())+ nl 
				+ "gx-hex: " + bi2strh(getGx())+ nl 
				+ "gy-hex: " + bi2strh(getGy())+ nl 

				;
	}

	public static void main(String[] args) {
		MyDomain md = new MyDomain("P-256"); 
		System.out.println(md);

	}

}
