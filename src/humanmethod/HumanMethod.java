package humanmethod;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 * 
 * @author Alessandro Mazzeo - jojo2234
 * @version 1.0.0
 * @description Resurging SUN packages for EC implementations
 */
public class HumanMethod {
    
    public static void main(String[] args){
        ECParameterSpec ecParams = (ECParameterSpec) gen_prime256v1();

        Optional<ECOperations> opsOpt = ECOperations.forParameters(ecParams);
        ECOperations ops = (ECOperations)opsOpt.get();
        IntegerFieldModuloP field = ops.getField();
        ECPoint genPoint = ecParams.getGenerator();
        ImmutableIntegerModuloP x = field.getElement(genPoint.getAffineX());
        ImmutableIntegerModuloP y = field.getElement(genPoint.getAffineY());
        AffinePoint affGen = new AffinePoint(x, y); //Point G static on this curve extracted from SunEC provider
        //Italian public key to verify COVID19 Digital Certificates:
        BigInteger myQx = new BigInteger("70899144226819986600466051744120390419306179699533960446833038039976773186538");
        BigInteger myQy = new BigInteger("39451825794351722093185790676827790492185744363571483016658958507009599105167");
        ECPoint Q = new ECPoint(myQx,myQy);
        //One Byte Only
        //It's possible understand the generation process of a public point(key)?
        //With a byte set 1 the G point is returned!
        //But a byte array like this: 00000000000000000000000000000001 return a different point!
        //That's because every byte in the byte array is processed even if zero.
        
        //byte[] privArr = {65, -30, 71, -120, 96, -20, 19, 96, 10, -30, -3, 122, 16, 22, 12, 12, -78, 60, 3, -114, 62, -108, 24, -107, -72, 109, 29, 119, 4, 61, -48, 0};
        //byte[] privArr = {-127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127, -127};
        byte[] privArr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        //byte[] privArr = {45,-30,-9,-2,-55,-71,96,65,-40,125,-116,111,46,-1,119,20,-122,11,-28,-126,-24,117,119,23,62,5,119,71,38,-124,62,-98};
        //byte[] privArr = {15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15};
        
        
        BigInteger bigPrv = new BigInteger(privArr);
        //privArr = new BigInteger("1").toByteArray(); //REMOVE COMMENT TO SEE THE DIFFERENCE
        
        int i=0;
        do{
            //System.out.println("\n\nLast byte s[i]: "+privArr[31]+"\n\n"); //Se è 1 ritorna il punto G MA SOLO SE FA l'ultimo byte se c'è altri byte ritorna altri punti
            System.out.println("Private key: "+bigPrv);
            Point pub = ops.multiply(affGen, privArr);
            AffinePoint affPub = pub.asAffine();
            //From affinPoint to Point (pub=result)
            //From result get t0,t1,t2,t3,t4 maybe trying to generate them with all the possible first byte s[0] (every s[0] possible)
            //However t0,t1,t... depends upon the previous s[i]...
            System.out.println("Public: "+affPub.getX().asBigInteger()+","+affPub.getY().asBigInteger());
            bigPrv = bigPrv.add(new BigInteger("1"));
            byte[] bigArrPrv = bigPrv.toByteArray();
            int q=31;
            System.out.print("PrivArr: ");
            for(int j=0;j<privArr.length;j++){
                System.out.print(privArr[j]);
            }
            System.out.print("\n\n");
            if(privArr.length>30){
                for(int j=bigArrPrv.length;j>0;j--){
                    privArr[q] = bigArrPrv[j-1];
                    q--;
                }
            }else{
                privArr = bigPrv.toByteArray();
            }
            i++;
        }while(i<5);
        /** 
        boolean trovato = false;
        int i=0;
        do{
            Point pub = ops.multiply(affGen, privArr); //Generating a new public key with the private
            AffinePoint affPub = pub.asAffine();
            ECPoint W = new ECPoint(affPub.getX().asBigInteger(), affPub.getY().asBigInteger());
            if(Q.equals(W)){
                System.out.println("Private Key: "+bigPrv);
                trovato = true;
            }
            bigPrv = bigPrv.subtract(new BigInteger("1"));
            privArr = bigPrv.toByteArray();
            i++;
            System.out.println(i);
        }while(trovato==false);*/
    }

    /**
     * @param args the command line arguments
     */
    public static void oldmain(String[] args) throws SignatureException, InvalidAlgorithmParameterException {
        ECParameterSpec ecParams = (ECParameterSpec) gen_prime256v1();

        Optional<ECOperations> opsOpt = ECOperations.forParameters(ecParams);
        ECOperations ops = (ECOperations)opsOpt.get();
        IntegerFieldModuloP field = ops.getField();

        //Italian public key to verify COVID19 Digital Certificates:
        BigInteger myQx = new BigInteger("70899144226819986600466051744120390419306179699533960446833038039976773186538");
        BigInteger myQy = new BigInteger("39451825794351722093185790676827790492185744363571483016658958507009599105167");
        ECPoint Q = new ECPoint(myQx,myQy);
        //Note: The library sunec.dll is used to verify a signature
        /**
        * Example public key
        BigInteger myQx = new BigInteger("112099522388764814483762992601786773986610355195307830540042445533863577952543");
        BigInteger myQy = new BigInteger("82504288555126164909288714840169646141833528480840266225025998846577653072959");
        privArr = {45,-30,-9,-2,-55,-71,96,65,-40,125,-116,111,46,-1,119,20,-122,11,-28,-126,-24,117,119,23,62,5,119,71,38,-124,62,-98};
        **/
        
        /*
        ImmutableIntegerModuloP Qx = field.getElement(myQx);
        ImmutableIntegerModuloP Qy = field.getElement(myQy);
        int numBits = ecParams.getOrder().bitLength();
        int seedBits = numBits + 64;
        int seedSize = (seedBits + 7) / 8;
        System.out.println("Numbits: "+numBits+" seedBits: "+seedBits+" seedSize: "+seedSize);*/
        
        /**
         *  Max private key:                      57669001306428065956053000376875938421040345304064124051023973211784186134399
         *  Max private key with every byte 15:   6811299366900952671974763824040465167839410862684739061144563765171360567055
            Every byte at 0:                      0
            PK first byte 65 others 0:            29400335157912315244266070412362164103369332044010299463143527189509193072640
            PK first byte 65 others 12:           29799725740296454967896817214471275119405911756887571729747627678351974206476
            PK first byte 65 others random:       29800136295302694869022804810320554474489315637186819418691211111982639730931
            PK first byte 127 others 0:           57443731770074831323412168344153766786583156455220123566449660816425654157312
            Minimum private key:                  -57214914681968002444588016121939907409851051246551808113614335627439428763263
            PK everything 0 except the last byte set to : 1

            X & Y are obviously connected with the private key seems that when the right side of the key grow (last 16 bytes), Y grows too. 
            * Instead with the left side of the bytearray X grows. 
         */
        
        /**
        byte[] privArr = {65, -30, 71, -120, 96, -20, 19, 96, 10, -30, -3, 122, 16, 22, 12, 12, -78, 60, 3, -114, 62, -108, 24, -107, -72, 109, 29, 119, 4, 61, -48, -13}; //this.generatePrivateScalar(random, ops, seedSize);
        ECPoint genPoint = ecParams.getGenerator();
        ImmutableIntegerModuloP x = field.getElement(genPoint.getAffineX());
        ImmutableIntegerModuloP y = field.getElement(genPoint.getAffineY());
        AffinePoint affGen = new AffinePoint(x, y); //Point G static on this curve extracted from SunEC provider

        //Conversion from ByteArray to BigInteger works, viceversa too!
        //BigInteger bigPrv = new BigInteger(privateByteArray);
        //privateByteArray = bigPrv.toByteArray();
        BigInteger bigPrv = new BigInteger(privArr);
        BigInteger maxPrv = new BigInteger("57669001306428065956053000376875938421040345304064124051023973211784186134399");
        boolean trovato = false;
        //System.out.println("Private Key: "+bigPrv);
        do{
            Point pub = ops.multiply(affGen, privArr); //Generating a new public key with the private
            AffinePoint affPub = pub.asAffine();
            ECPoint W = new ECPoint(affPub.getX().asBigInteger(), affPub.getY().asBigInteger());
            if(Q.equals(W)){
                System.out.println("Private Key: "+bigPrv);
                trovato = true;
            }
            bigPrv = bigPrv.add(new BigInteger("1"));
            privArr = bigPrv.toByteArray();
        }while(trovato!=false && bigPrv.compareTo(maxPrv) == -1); //Rimettere == false per loopare
        **/
        //Last execution 153 minutes e 13 seconds
        //System.out.println("\nW: "+W.getAffineX()+","+W.getAffineY());
        /**
         * System.out.println("Private Key: "+bigPrv);
         * Point pub = ops.multiply(affGen, privArr); //Generating a new public key with the private
         * AffinePoint affPub = pub.asAffine();
         * System.out.println("\nQ: "+myQx+","+myQy);
         * System.out.println("\nQ intersect prime256v1: "+intersect_prime256v1(myQx,myQy)+" \n");
         * 
         * ECPoint G = new ECPoint(new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
         * System.out.println("\nG: "+G.getAffineX()+","+G.getAffineY());
         * System.out.println("\nG intersect prime256v1: "+intersect_prime256v1(G.getAffineX(),G.getAffineY())+" \n");
         * 
         * ECPoint F = sumPoints_prime256v1(G,G); //Not working with the same point but if private key is 1 should be G+G
         * System.out.println("\nF: "+F.getAffineX()+","+F.getAffineY());
         * System.out.println("\nF intersect prime256v1: "+intersect_prime256v1(F.getAffineX(),F.getAffineY())+" \n");
         * 
         * System.out.println("W: "+affPub);
         * ECPoint W = new ECPoint(affPub.getX().asBigInteger(), affPub.getY().asBigInteger());
         * System.out.println("\nW intersect prime256v1: " + intersect_prime256v1(W.getAffineX(),W.getAffineY()));
         * 
         * try {
         * PublicKey publicKey = new ECPublicKeyImpl(W, ecParams);
         * byte[] pb = publicKey.getEncoded();
         * System.out.print("\nPubblica Encoded: \n"+pb[0]);
         * for(int j=1;j<pb.length;j++){
         * System.out.print(","+pb[j]);
         * }
         * System.out.println("\n");
         * } catch (InvalidKeyException ex) {
         * Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
         * }
         **/
        byte[] newPriv = {48,-127,-121,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-122,72,-50,61,3,1,7,4,109,48,107,2,1,1,4,32,19,-84,-107,21,-57,78,13,95,57,26,94,-11,-20,-34,-13,58,48,-96,-1,80,12,-113,13,109,-98,-88,-1,-66,-28,-127,-32,8,-95,68,3,66,0,4,112,21,0,-105,100,70,-42,-102,68,108,105,0,-117,53,37,84,-102,-102,90,-77,-14,61,-124,-62,68,-5,-90,14,-127,-57,-34,119,2,12,70,57,110,72,-119,111,-67,117,-81,118,121,99,-112,116,114,39,92,48,119,-3,-98,-53,-52,-46,15,30,-4,-30,-84,-32};
        KeyFactory fattoria;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","SunEC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"),SecureRandom.getInstance("SHA1PRNG","SUN"));
            PKCS8EncodedKeySpec pkey = new PKCS8EncodedKeySpec(newPriv);
            EncodedKeySpec specPriv = (EncodedKeySpec)pkey;
            fattoria = KeyFactory.getInstance("EC","SunEC");
            PrivateKey priv = fattoria.generatePrivate(specPriv); //Something went wrong! //java.security.spec.InvalidKeySpecException: Only ECPrivateKeySpec and PKCS8EncodedKeySpec supported for EC private keys
        try {
            Signature dsa = Signature.getInstance("SHA256withECDSA");
            dsa.initSign(priv);
            byte[] dataToBeSigned = {127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127};
            dsa.update(dataToBeSigned);
            byte[] firma = dsa.sign();
            for(int i=0;i<firma.length;i++){
                System.out.print(firma[i]+",");
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
        }   catch (InvalidKeyException ex) {
                Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(HumanMethod.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * 
     * @return NamedCurve: A curve y²=x³+ax+b mod primeN with G point as (48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)
     */
    public static NamedCurve gen_prime256v1(){
        //Curva y²=x³+ax+b mod primeN
        String name = "secp256r1 [NIST P-256, X9.62 prime256v1]";
        String oid = "1.2.840.10045.3.1.7";
        //new EllipticCurve(field.p,a,b)
        EllipticCurve ec = new EllipticCurve(new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
        ECPoint G = new ECPoint(new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
        BigInteger n = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");
        int h = 1;
        return new NamedCurve(name,oid,ec,G,n,h);
    }
    
    /**
     * 
     * @param A
     * @param B : Should be equals or greater than A
     * @return An ECPoint as the addition of two points on a EC: Curve y²=x³+ax+b mod primeN; p3 = (x3,y3); x3=S²-x1-x2 mod primeN; y3=S(x1-x3)-y1 mod primeN; If p1 != p2 Than S=(y2-y1)/(x2-x1); If p1 == p2 Than S=((b*x1²)+a)/(a*y1);
     */
    private static ECPoint sumPoints_prime256v1(ECPoint A, ECPoint B){
        ECPoint C = null;
        BigInteger S, x3, y3;
        BigInteger a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
        BigInteger b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
        BigInteger p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"); 
        if(A.equals(B)){ //It's working on my custom curve but not on this!
            BigInteger quad_x1 = A.getAffineX().multiply(A.getAffineX());
            BigInteger b_mul = b.multiply(quad_x1);
            BigInteger num = b_mul.add(a);
            BigInteger a_mul = a.multiply(A.getAffineY());
            BigInteger den = a_mul.mod(p);         
            S=(num.mod(p)).multiply(den.modInverse(p));          
            //S=(((b.multiply((A.getAffineX().multiply(A.getAffineX())))).add(a)).mod(p)).divide((a.multiply(A.getAffineY())).mod(p));
        }else{
            BigInteger sub2 = B.getAffineX().abs().subtract(A.getAffineX().abs());
            BigInteger sub1 = B.getAffineY().abs().subtract(A.getAffineY().abs());
            
            if(sub2.equals(BigInteger.ZERO)){
                S=(sub1.mod(p)).multiply(BigInteger.ZERO);
            }else{
                S=(sub1.mod(p)).multiply(sub2.modInverse(p));
            }
            //S=((B.getAffineY().subtract(A.getAffineY())).mod(p)).divide((B.getAffineX().subtract(A.getAffineX())).mod(p));
        }
        S=S.mod(p);
        x3 = ((S.multiply(S)).subtract(A.getAffineX()).subtract(B.getAffineX())).mod(p);
        y3 = ((S.multiply((A.getAffineX().subtract(x3)))).subtract(A.getAffineY())).mod(p);
        C = new ECPoint(x3,y3);
        return C;
    }
    
    /**
     * 
     * @param x
     * @param y
     * @return true if the point interesct the curve secp256r1
     */
    private static boolean intersect_prime256v1(BigInteger x, BigInteger y){
        BigInteger a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
        BigInteger b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
        BigInteger p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
        BigInteger QuadY = y.multiply(y);
        BigInteger CubeX = x.multiply(x.multiply(x));
        BigInteger ax = x.multiply(a);
        BigInteger summed = (CubeX.add(ax.add(b))).mod(p);
        return summed.equals(QuadY.mod(p));
    }
}
