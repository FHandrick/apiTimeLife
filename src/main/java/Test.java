

import apiTimeLIfe.APITimeLine;


public class Test {

	public static void main(String[] args) throws Exception {
		
	
		/*String csvFile = "boucyCastlecommits.csv";
		String prologFile = "boucyCastle";
		APITimeLine diff = new APITimeLine("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
		*/
		String csvFile = "googleTinkcommits.csv";
		String prologFile = "googletink";
		APITimeLine diff = new APITimeLine("google/tink", "https://github.com/google/tink.git");
		
    	diff.setPath("/home/francisco/github");
    		
    	diff.createPrologFile(csvFile,prologFile);
    	
        System.out.println( "========================Finish====================================" );
    	
	}
}