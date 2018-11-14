import java.util.ArrayList;

import apiTimeLIfe.APIDiff;
import apiTimeLIfe.Change;
import apiTimeLIfe.Result;
import apiTimeLIfe.enums.Classifier;
import apiTimeLIfe.util.UtilFile;

public class Test {

	public static void main(String[] args) throws Exception {
		
		String file = "";
		char ch='"';
		APIDiff diff = new APIDiff("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
    	diff.setPath("/home/francisco/github");
    	
    
    	Release re = new Release();
    	re.distribute();
    	ArrayList<String> prologLine = new ArrayList<String>();
    	for (int i = 0; i<re.comparison.size();i++) {
    		prologLine.clear();
    		//System.out.println(re.comparison.get(i).commitBegin+ " Compared with: "+re.comparison.get(i).commitFinal);
    		//System.out.println( "================"+"Comparation Number:"+i+"===========================================" );
    		file = (re.comparison.get(i).commitBegin+"_"+re.comparison.get(i).commitFinal+".pl");
        	Result result = diff.detectChangeBetweenCommits(re.comparison.get(i).commitBegin, re.comparison.get(i).commitFinal,Classifier.API);

        	prologLine.add("/* facts */"+"\n");
        	
        	for(Change changeMethod : result.getChangeMethod()){
        		
        	    if (changeMethod.getCategory().name().toString() == "METHOD_MOVE") {
        	    		    	
        	      	String aux = (changeMethod.getDescription()).substring(12, (changeMethod.getDescription()). lastIndexOf("</code><br>moved from"));
        	    	
        	      	prologLine.add("method(1,"+ch+aux+ch+","+ch+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>moved from")+28,(changeMethod.getDescription()).lastIndexOf("</code><br>to")).replace(".","-").toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>to")+20, (changeMethod.getDescription()).length()-11)+ch+").");
        	    	  	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_RENAME") {
        	    	
        	    	String aux = (changeMethod.getDescription()).substring(13, (changeMethod.getDescription()). lastIndexOf("</code><br>renamed to"));
        	    	
        	    	prologLine.add("method(2,"+ch+aux+ch+","+ch+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>renamed to")+28,(changeMethod.getDescription()).lastIndexOf("</code><br>in <code>"))+ch+","+ch+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in")+20, (changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    }
        	    
        	    if (changeMethod.getCategory().name().toString() == "METHOD_REMOVE") {
        	    	
        	    	prologLine.add("method(3,"+ch+(changeMethod.getDescription()).substring(17, (changeMethod.getDescription()).lastIndexOf("</code><br>removed"))+ch+
        					","+ch+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>removed")+30, 
        							(changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_PUSH_DOWN") {
        	    	System.out.println(changeMethod.getCategory().name().toString());
        	    	System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_INLINE") {
        	    	
        	    	String aux = (changeMethod.getDescription()).substring(17, (changeMethod.getDescription()). lastIndexOf("</code><br>from"));
        	  
        	    	prologLine.add("method(5,"+ch+aux+ch+","+ch+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>from")+22,
        	    					(changeMethod.getDescription()).lastIndexOf("</code><br>inlined to"))+ch+").");
        	    			
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_PARAMETER_LIST") {
        	    	System.out.println(changeMethod.getCategory().name().toString());
        	    	System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_EXCEPTION_LIST") {
        	    	
        	    	prologLine.add("method(7,"+ch+(changeMethod.getDescription()).substring(10, (changeMethod.getDescription()).lastIndexOf(")</code><br>")+1)+ch+
        					","+ch+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in ")+20, 
        							(changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_RETURN_TYPE") {
        	    	
        	    	prologLine.add("method(8,"+ch+(changeMethod.getDescription()).substring(17, (changeMethod.getDescription()).lastIndexOf("</code><br>changed the return type"))+ch+
        					","+ch+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>changed the return type")+47, 
        							(changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_LOST_VISIBILITY") {
        	    
        	    	prologLine.add("method(9,"+ch+(changeMethod.getDescription()).substring(18, (changeMethod.getDescription()). lastIndexOf("</code><br> changed visibility"))+ch+
        					","+ch+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in <code>")+20, 
        							(changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_ADD_MODIFIER_FINAL") {
        	    	
        	    	prologLine.add("method(10,"+(changeMethod.getDescription()).substring(13, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("<code>final</code><br>in")+31, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_REMOVE_MODIFIER_STATIC") {
        	    
        	    	prologLine.add("method(11,"+ch+(changeMethod.getDescription()).substring(13, (changeMethod.getDescription()).lastIndexOf(")</code><br>")+1)+ch+
        					","+ch+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in class ")+26, 
        							(changeMethod.getDescription()).length()-11)+ch+").");
        	    	
        	    }	    
        	    
        	}
        	
        	/*
        	for(Change changeType : result.getChangeType()){
        		
        		if (changeType.getCategory().name().toString() == "TYPE_RENAME") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_MOVE") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_MOVE_AND_RENAME") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_REMOVE") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_LOST_VISIBILITY") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_ADD_MODIFIER_FINAL") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_REMOVE_MODIFIER_STATIC") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_CHANGE_SUPERCLASS") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        		if (changeType.getCategory().name().toString() == "TYPE_REMOVE_SUPERCLASS") {
        			System.out.println("\n" + changeType.getCategory().getDisplayName() + " - " + changeType.getDescription());
        		}
        	}
        	*/
    		
        	prologLine.add("\n");
        	prologLine.add("method_move_count(Y):-findall(X,method(1,A,B,C),L),length(L,Y).");
        	prologLine.add("method_rename_count(Y):-findall(X,method(2,A,B,C),L),length(L,Y).");
        	prologLine.add("method_remove_count(Y):-findall(X,method(3,A,B),L),length(L,Y).");
        	prologLine.add("method_inline_count(Y):-findall(X,method(5,A,B),L),length(L,Y).");
        	prologLine.add("method_change_exception_list_count(Y):-findall(X,method(7,A,B),L),length(L,Y).");
        	prologLine.add("method_change_return_type_count(Y):-findall(X,method(8,A,B),L),length(L,Y).");
        	prologLine.add("method_lost_visibility_count(Y):-findall(X,method(9,A,B),L),length(L,Y).");
        	prologLine.add("method_add_modifier_final_count(Y):-findall(X,method(10,A,B),L),length(L,Y).");
        	prologLine.add("method_remove_modifier_static_count(Y):-findall(X,method(11,A,B),L),length(L,Y).");
        	prologLine.add("\n");
        	prologLine.add("all_method_change(A,B,C,D,E,F,G,H,I):-method_move_count(A),method_rename_count(B),method_remove_count(C),");
        	prologLine.add("method_inline_count(D),method_change_exception_list_count(E),method_change_return_type_count(F),method_lost_visibility_count(G),");
        	prologLine.add("method_add_modifier_final_count(H),method_remove_modifier_static_count(I).");
        	
        	UtilFile.writeFile(file, prologLine);
        	
    	}
    		
        System.out.println( "========================Finish====================================" );
    	
	}
}