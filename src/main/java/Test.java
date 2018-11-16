

import apiTimeLIfe.APITimeLine;


public class Test {

	public static void main(String[] args) throws Exception {
		
	
		String csvFile = "commits.csv";
		APITimeLine diff = new APITimeLine("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
    	diff.setPath("/home/francisco/github");
    		
    	diff.createPrologFile(csvFile);
    	
        System.out.println( "========================Finish====================================" );
    	
	}
}