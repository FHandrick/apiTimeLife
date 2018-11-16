package apiTimeLIfe;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.eclipse.jgit.diff.DiffEntry.ChangeType;

import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import apiTimeLIfe.enums.Classifier;
import apiTimeLIfe.internal.analysis.DiffProcessor;
import apiTimeLIfe.internal.analysis.DiffProcessorImpl;
import apiTimeLIfe.internal.service.git.GitFile;
import apiTimeLIfe.internal.service.git.GitService;
import apiTimeLIfe.internal.service.git.GitServiceImpl;
import apiTimeLIfe.internal.util.UtilTools;
import apiTimeLIfe.internal.visitor.APIVersion;
import apiTimeLIfe.util.Release;
import apiTimeLIfe.util.UtilFile;



public class APITimeLine implements DiffDetector{
	
	private String nameProject;
	
	private String path;
	
	private String url;
	
	private Logger logger = LoggerFactory.getLogger(APITimeLine.class);

	public APITimeLine(final String nameProject, final String url) {
		this.url = url;
		this.nameProject = nameProject;
	}
	
	public String getPath() {
		return path;
	}
	public String getNamePeoject() {
		return nameProject;
	}

	public void setPath(String path) {
		this.path = path;
	}
	
	public void createPrologFile(String csvFIle) throws Exception {
		
		ArrayList<String> release = new ArrayList<String>();
	    BufferedReader br = null;
	    String linha = "";
	    String file = "";
	    String csvDivisor = ",";
	    char ch='"';
	    try {

	        br = new BufferedReader(new FileReader(csvFIle));
	        while ((linha = br.readLine()) != null) {

	            String[] commit = linha.split(csvDivisor);
	            release.add(commit[0]);
	            
	        }

	    } catch (FileNotFoundException e) {
	        e.printStackTrace();
	    } catch (IOException e) {
	        e.printStackTrace();
	    } finally {
	        if (br != null) {
	            try {
	                br.close();
	            } catch (IOException e) {
	                e.printStackTrace();
	            }
	        }
	    }
	    
	    
	    Release re = new Release();
    	re.distribute(release);
    	ArrayList<String> prologLine = new ArrayList<String>();
    	for (int i = 0; i<re.comparison.size();i++) {
    		prologLine.clear();
    		
    		file = (re.comparison.get(i).commitBegin+"_"+re.comparison.get(i).commitFinal+".pl");
        	Result result = this.detectChangeBetweenCommits(re.comparison.get(i).commitBegin, re.comparison.get(i).commitFinal,Classifier.API);
        	
        	prologLine.add("/* facts */"+"\n");
        	prologLine.add("/* metohod(1...  - Move Method */");
        	prologLine.add("/* metohod(2...  - Rename Method */");
        	prologLine.add("/* metohod(3...  - Remove Method */");
        	prologLine.add("/* metohod(4...  - Push Down Method */");
        	prologLine.add("/* metohod(5...  - Inline Method */");
        	prologLine.add("/* metohod(6...  - Change in Parameter List Method */");
        	prologLine.add("/* metohod(7...  - Change in Exception LIst Method*/");
        	prologLine.add("/* metohod(8...  - Change in Return TYpe Method */");
        	prologLine.add("/* metohod(9...  - Lost Visibility Method */");
        	prologLine.add("/* metohod(10...  - Add Final Modifier */");
        	prologLine.add("/* metohod(11...  - Remove Static Modifier */"+"\n");
        	
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
	}
	@Override
	public Result detectChangeAtCommit(String commitId, Classifier classifierAPI) {
		Result result = new Result();
		try {
			GitService service = new GitServiceImpl();
			
			Repository repository = service.openRepositoryAndCloneIfNotExists(this.path, this.nameProject, this.url);
			RevCommit commit = service.createRevCommitByCommitId(repository, commitId);
			Result resultByClassifier = this.diffCommit(commit, repository, this.nameProject, classifierAPI);
			result.getChangeType().addAll(resultByClassifier.getChangeType());
			result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
			result.getChangeField().addAll(resultByClassifier.getChangeField());
			
			
		} catch (Exception e) {
			this.logger.error("Error in calculating commitn diff ", e);
		}
		this.logger.info("Finished processing.");
		return result;
	}
	
	@Override
	public Result detectChangeByDate(String branch, List<Classifier> classifiers, String dt) throws Exception {
		Result result = new Result();
		GitService service = new GitServiceImpl();
		Repository repository = service.openRepositoryAndCloneIfNotExists(this.path, this.nameProject, this.url);
		RevWalk revWalk = service. createAllRevsWalk(repository, branch);
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		
		Iterator<RevCommit> i = revWalk.iterator();
		while(i.hasNext()){
			RevCommit currentCommit = i.next();
			
			Date d1 = sdf.parse(dt);
			Date d2 = new Date(currentCommit.getCommitTime() * 1000L);
			
			if (d1.compareTo(d2) < 0) {
			
				for(Classifier classifierAPI: classifiers){
					Result resultByClassifier = this.diffCommit(currentCommit, repository, this.nameProject, classifierAPI);
					result.getChangeType().addAll(resultByClassifier.getChangeType());
					result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
					result.getChangeField().addAll(resultByClassifier.getChangeField());
				}
				System.out.println(d2);
				
			}
			else {
				break;
			}
			
		}
		this.logger.info("Finished processing.");
		return result;
	}
	
	@Override
	public Result detectChangeAllHistory(String branch, List<Classifier> classifiers) throws Exception {
		Result result = new Result();
		GitService service = new GitServiceImpl();
		Repository repository = service.openRepositoryAndCloneIfNotExists(this.path, this.nameProject, this.url);
		RevWalk revWalk = service. createAllRevsWalk(repository, branch);
		int controller = 0;
		Iterator<RevCommit> i = revWalk.iterator();
		while(i.hasNext()){
			RevCommit currentCommit = i.next();
			for(Classifier classifierAPI: classifiers){
				Result resultByClassifier = this.diffCommit(currentCommit, repository, this.nameProject, classifierAPI);
				result.getChangeType().addAll(resultByClassifier.getChangeType());
				result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
				result.getChangeField().addAll(resultByClassifier.getChangeField());
			}
			controller++;
			if (controller>3000)
				break;
			
		}
		this.logger.info("Finished processing.");
		return result;
	}
	
	public Result detectChangeBetweenCommits(final String rev1, final String rev2, List<Classifier> classifiers) throws Exception {
		
		Result result = new Result();
		try {
			GitService service = new GitServiceImpl();
			
			Repository repository = service.openRepositoryAndCloneIfNotExists(this.path, this.nameProject, this.url);		
			RevWalk walk = service.createRevsWalkBetweenCommits(repository, rev1, rev2);	
			Iterator<RevCommit> i = walk.iterator();
			int control = 0;
			while(i.hasNext()){
				RevCommit currentCommit = i.next();
				for(Classifier classifierAPI: classifiers){
					Result resultByClassifier = this.diffCommit(currentCommit, repository, this.nameProject, classifierAPI);
					result.getChangeType().addAll(resultByClassifier.getChangeType());
					result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
					result.getChangeField().addAll(resultByClassifier.getChangeField());
				}
				if (control == 15)
					break;
				control++;
			}
						
		} catch (Exception e) {
			this.logger.error("Error in calculating commitn diff ", e);
		}
		this.logger.info("Finished processing.");
		return result;
		
		
	}
	
	@Override
	public Result detectChangeAllHistory(List<Classifier> classifiers) throws Exception {
		return this.detectChangeAllHistory(null, classifiers);
	}
	
	@Override
	public Result fetchAndDetectChange(List<Classifier> classifiers) {
		Result result = new Result();
		try {
			GitService service = new GitServiceImpl();
			Repository repository = service.openRepositoryAndCloneIfNotExists(this.path, this.nameProject, this.url);
			RevWalk revWalk = service.fetchAndCreateNewRevsWalk(repository, null);
			//Commits.
			Iterator<RevCommit> i = revWalk.iterator();
			while(i.hasNext()){
				RevCommit currentCommit = i.next();
				for(Classifier classifierAPI : classifiers){
					Result resultByClassifier = this.diffCommit(currentCommit, repository, this.nameProject, classifierAPI);
					result.getChangeType().addAll(resultByClassifier.getChangeType());
					result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
					result.getChangeField().addAll(resultByClassifier.getChangeField());
				}
			}
		} catch (Exception e) {
			this.logger.error("Error in calculating commit diff ", e);
		}

		this.logger.info("Finished processing.");
		return result;
	}
	@Override
	public Result detectChangeBetweenCommits(String rev1, String rev2, Classifier classifier) throws Exception {
		return this.detectChangeBetweenCommits(rev1, rev2, Arrays.asList(classifier));
	}
	
	
	@Override
	public Result detectChangeByDate(String branch, Classifier classifier, String dt) throws Exception {
		return this.detectChangeByDate(branch, Arrays.asList(classifier), dt);
	}
	
	
	@Override
	public Result detectChangeAllHistory(String branch, Classifier classifier) throws Exception {
		return this.detectChangeAllHistory(branch, Arrays.asList(classifier));
	}
	


	@Override
	public Result detectChangeAllHistory(Classifier classifier) throws Exception {
		return this.detectChangeAllHistory(Arrays.asList(classifier));
	}

	@Override
	public Result fetchAndDetectChange(Classifier classifier) throws Exception {
		return this.fetchAndDetectChange(Arrays.asList(classifier));
	}
		
	private Result diffCommit(final RevCommit currentCommit, final Repository repository, String nameProject, Classifier classifierAPI) throws Exception{
		File projectFolder = new File(UtilTools.getPathProject(this.path, nameProject));
		if(currentCommit.getParentCount() != 0){//there is at least one parent
			try {
				APIVersion version1 = this.getAPIVersionByCommit(currentCommit.getParent(0).getName(), projectFolder, repository, currentCommit, classifierAPI);//old version
				APIVersion version2 = this.getAPIVersionByCommit(currentCommit.getId().getName(), projectFolder, repository, currentCommit, classifierAPI); //new version
				DiffProcessor diff = new DiffProcessorImpl();
				return diff.detectChange(version1, version2, repository, currentCommit);
			} catch (Exception e) {
				this.logger.error("Error during checkout [commit=" + currentCommit + "]");
			}
		}
		return new Result();
	}
	
	private APIVersion getAPIVersionByCommit(String commit, File projectFolder, Repository repository, RevCommit currentCommit, Classifier classifierAPI) throws Exception{
		
		GitService service = new GitServiceImpl();
		
		//Finding changed files between current commit and parent commit.
		Map<ChangeType, List<GitFile>> mapModifications = service.fileTreeDiff(repository, currentCommit);
		
		service.checkout(repository, commit);
		return new APIVersion(this.path, projectFolder, mapModifications, classifierAPI);
	}

}
