import java.io.FileWriter;
import java.io.PrintWriter;

import apidiff.APIDiff;
import apidiff.Change;
import apidiff.Result;
import apidiff.enums.Classifier;

public class Test {

	public static void main(String[] args) throws Exception {
		
		
		FileWriter file;

		APIDiff diff = new APIDiff("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
    	diff.setPath("/home/francisco/github");
    	
    	Release re = new Release();
    	re.insert();
    	
    	for (int i = 0; i<re.comparations.size();i++) {
    		System.out.println(re.comparations.get(i).commitBegin+ " Compared with: "+re.comparations.get(i).commitFinal);
    		System.out.println( "================"+"Comparation Number:"+i+"===========================================" );
    		
    		
        	file = new FileWriter(re.comparations.get(i).commitBegin+"_"+re.comparations.get(i).commitFinal+".pl");
        	PrintWriter recordFile = new PrintWriter(file);
        	Result result = diff.detectChangeBetweenCommits(re.comparations.get(i).commitBegin, re.comparations.get(i).commitFinal,Classifier.API);
        	
        	recordFile.printf("/* facts */"+"\n");
        	
        	for(Change changeMethod : result.getChangeMethod()){
        	    
        	    
        	    if (changeMethod.getCategory().name().toString() == "METHOD_MOVE") {
        	    	
        	    	
        	      	String aux = (changeMethod.getDescription()).substring(12, (changeMethod.getDescription()). lastIndexOf("</code><br>moved from"));
        	    	aux = aux.substring(0,aux.lastIndexOf("("));
        	    	recordFile.printf("\n"+"method(1,"+aux.toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>moved from")+28,(changeMethod.getDescription()).lastIndexOf("</code><br>to")).replace(".","-").toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>to")+20, (changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_RENAME") {
        	    	
        	    	String aux = (changeMethod.getDescription()).substring(13, (changeMethod.getDescription()). lastIndexOf("</code><br>renamed to"));
        	    	aux = aux.substring(0,aux.lastIndexOf("("));
        	    	
        	    	recordFile.printf("\n"+"method(2,"+aux.toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>renamed to")+28,(changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in")+20, (changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    }
        	    
        	    if (changeMethod.getCategory().name().toString() == "METHOD_REMOVE") {
        	    	
        	    	recordFile.printf("\n"+"method(3,"+(changeMethod.getDescription()).substring(17, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>removed")+30, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_PUSH_DOWN") {
        	    	System.out.println(changeMethod.getCategory().name().toString());
        	    	System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_INLINE") {
        	    	
        	    	String aux = (changeMethod.getDescription()).substring(17, (changeMethod.getDescription()). lastIndexOf("</code><br>from"));
        	    	aux = aux.substring(0,aux.lastIndexOf("("));
        	    
        	    	recordFile.printf("\n"+"method(5,"+aux.toLowerCase()+","+
        	    			(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>from")+22,
        	    					(changeMethod.getDescription()).lastIndexOf("</code><br>inlined to")).replace(".","-").toLowerCase()+").");
        	    			
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_PARAMETER_LIST") {
        	    	System.out.println(changeMethod.getCategory().name().toString());
        	    	System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_EXCEPTION_LIST") {
        	    	
        	    	recordFile.printf("\n"+"method(7,"+(changeMethod.getDescription()).substring(10, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in ")+20, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_CHANGE_RETURN_TYPE") {
        	    	
        	    	recordFile.printf("\n"+"method(8,"+(changeMethod.getDescription()).substring(17, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>changed the return type")+47, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_LOST_VISIBILITY") {
        	    
        	    	recordFile.printf("\n"+"method(9,"+(changeMethod.getDescription()).substring(18, (changeMethod.getDescription()). lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in <code>")+20, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_ADD_MODIFIER_FINAL") {
        	    	
        	    	recordFile.printf("\n"+"method(10,"+(changeMethod.getDescription()).substring(13, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("<code>final</code><br>in")+31, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
        	    	
        	    }
        	    if (changeMethod.getCategory().name().toString() == "METHOD_REMOVE_MODIFIER_STATIC") {
        	    
        	    	recordFile.printf("\n"+"method(11,"+(changeMethod.getDescription()).substring(13, (changeMethod.getDescription()).lastIndexOf("(")).toLowerCase()+
        					","+(changeMethod.getDescription()).substring((changeMethod.getDescription()).lastIndexOf("</code><br>in class ")+26, 
        							(changeMethod.getDescription()).length()-11).replace(".","-").toLowerCase()+").");
        	    	
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
    		
        	recordFile.printf("\n");
        	recordFile.printf("\n"+"method_move_count(Y):-findall(X,method(1,A,B,C),L),length(L,Y).");
        	recordFile.printf("\n"+"method_rename_count(Y):-findall(X,method(2,A,B,C),L),length(L,Y).");
        	recordFile.printf("\n"+"method_remove_count(Y):-findall(X,method(3,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_inline_count(Y):-findall(X,method(5,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_change_exception_list_count(Y):-findall(X,method(7,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_change_return_type_count(Y):-findall(X,method(8,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_lost_visibility_count(Y):-findall(X,method(9,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_add_modifier_final_count(Y):-findall(X,method(10,A,B),L),length(L,Y).");
        	recordFile.printf("\n"+"method_remove_modifier_static_count(Y):-findall(X,method(11,A,B),L),length(L,Y).");
        	recordFile.printf("\n");
        	recordFile.printf("\n"+"all_method_change(A,B,C,D,E,F,G,H,I):-method_move_count(A),method_rename_count(B),method_remove_count(C),");
        	recordFile.printf("\n"+"method_inline_count(D),method_change_exception_list_count(E),method_change_return_type_count(F),method_lost_visibility_count(G),");
        	recordFile.printf("\n"+"method_add_modifier_final_count(H),method_remove_modifier_static_count(I).");

        
        	recordFile.close();
        	
    	}
    		
        System.out.println( "========================Finish====================================" );
    	
	}
}