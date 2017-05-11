package net.meeusen.crypto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class EccBasics {

	public static void main(String[] args) {
		System.out.println("ecc basics with curves and points");

		System.out.println("ECCurve.Fp.getAllCoordinateSystems()");
		int[] coordsys = ECCurve.Fp.getAllCoordinateSystems();
		for ( int c: coordsys) {
			System.out.println(coord2string(c));; 
		}

		MyEccDomain dom256 = new MyEccDomain("P-256"); 

		System.out.println(dom256);

		java.security.spec.ECPoint generator =dom256.getG();
		BigInteger gx = generator.getAffineX();
		BigInteger gy = generator.getAffineY(); 

		ECCurve.Fp curve = new ECCurve.Fp(dom256.getPrime(), dom256.getA(), dom256.getB() );
		System.out.println("this curve's coord system: " + coord2string(curve.getCoordinateSystem()) );


		//new ECPoint.Fp(curve, x, y); // Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression); 
		ECPoint generatorbc = curve.createPoint(gx, gy);

		System.out.println("printpoint: GENERATOR of P-256: ");
		printpoint(generatorbc); 		
		System.out.println();

		System.out.println("printpoint: p1 =  666*G");
		ECPoint mypoint1 = generatorbc.multiply(new BigInteger("666"));
		printpoint(mypoint1); 
		System.out.println("normalized p1");
		printpoint(mypoint1.normalize());
		System.out.println();

		System.out.println("manual normalization of p1, assuming Jacobian coord i.e. IEEE P1363");
		System.out.println("z[0] of p1: " + mypoint1.getZCoord(0));
		ECFieldElement p1_z_inv = mypoint1.getZCoord(0).invert();
		System.out.println("inverse of z[0] of p1: p1_z_inv=" + p1_z_inv.toString());
		System.out.println("z[0] : " + mypoint1.getZCoord(0).negate());

		System.out.println("p1_x * p1_z_inv^2 =" + mypoint1.getXCoord().multiply(p1_z_inv).multiply(p1_z_inv));
		System.out.println("p1_y * p1_z_inv^3 =" + mypoint1.getYCoord().multiply(p1_z_inv).multiply(p1_z_inv).multiply(p1_z_inv));


		//		.multiply(p1_z_inv.toBigInteger()); 

		//System.out.println(mypoint1.getYCoord().multiply(p1_z_inv));
		//		ECPoint mypoint2 = generatorbc.multiply(new BigInteger("123456789123456789")); 
		//		
		//		System.out.println("p1 normal? "+mypoint1.isNormalized());
		//		System.out.println("p2 normal? "+mypoint2.isNormalized());
		//		
		//		printpoint(mypoint1);
		//		
		//		
		//		ECPoint point1_normal = mypoint1.normalize(); 
		//		
		//		printpoint(point1_normal);

	}

	private static void printpoint(ECPoint p) {
		if ( ! p.isValid()) {
			System.out.println("invalid point! not printable ");	
		} else {
			boolean isNormal = p.isNormalized(); 
			System.out.println("normalized? "+isNormal);
			System.out.println("x coord default "+p.getXCoord());
			System.out.println("y coord default "+p.getYCoord());
			for ( ECFieldElement zi : p.getZCoords() ) {
				System.out.println("zi " + zi.toString());
			}
			System.out.println("z[0] looks like the actual z; z[1] seems to be some Jacobian internal stuff. Not sure why it is in API...");
		}
	}

	private static String coord2string (int coordsystem) {
		switch (coordsystem) {
		case ECCurve.COORD_AFFINE: return "COORD_AFFINE";					
		case ECCurve.COORD_HOMOGENEOUS: return "COORD_HOMOGENEOUS";					
		case ECCurve.COORD_JACOBIAN: return "COORD_JACOBIAN";					
		case ECCurve.COORD_JACOBIAN_CHUDNOVSKY: return "COORD_JACOBIAN_CHUDNOVSKY";					
		case ECCurve.COORD_JACOBIAN_MODIFIED: return "COORD_JACOBIAN_MODIFIED";					
		case ECCurve.COORD_LAMBDA_AFFINE: return "COORD_LAMBDA_AFFINE";					
		case ECCurve.COORD_LAMBDA_PROJECTIVE: return "COORD_LAMBDA_PROJECTIVE";					
		case ECCurve.COORD_SKEWED: return "COORD_SKEWED";
		}
		return null;
	}


}
