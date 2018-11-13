package apiTimeLIfe;
import java.io.File;
import java.text.SimpleDateFormat;
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

public class APIDiff implements DiffDetector{
	
	private String nameProject;
	
	private String path;
	
	private String url;
	
	private Logger logger = LoggerFactory.getLogger(APIDiff.class);

	public APIDiff(final String nameProject, final String url) {
		this.url = url;
		this.nameProject = nameProject;
	}
	
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
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
			//int control = 0;
			while(i.hasNext()){
				RevCommit currentCommit = i.next();
				for(Classifier classifierAPI: classifiers){
					Result resultByClassifier = this.diffCommit(currentCommit, repository, this.nameProject, classifierAPI);
					result.getChangeType().addAll(resultByClassifier.getChangeType());
					result.getChangeMethod().addAll(resultByClassifier.getChangeMethod());
					result.getChangeField().addAll(resultByClassifier.getChangeField());
				}
				//if (control == 15)
				//	break;
				//control++;
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
