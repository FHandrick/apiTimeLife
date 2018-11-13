package apiTimeLIfe.internal.analysis;

import java.util.List;
import java.util.Map;

import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;

import apiTimeLIfe.Result;
import apiTimeLIfe.internal.refactor.RefactorProcessor;
import apiTimeLIfe.internal.refactor.RefactoringProcessorImpl;
import apiTimeLIfe.internal.visitor.APIVersion;
import refdiff.core.api.RefactoringType;
import refdiff.core.rm2.model.refactoring.SDRefactoring;

public class DiffProcessorImpl implements DiffProcessor {

	@Override
	public Result detectChange(final APIVersion version1, final APIVersion version2, final Repository repository, final RevCommit revCommit) {
		Result result = new Result();
		Map<RefactoringType, List<SDRefactoring>> refactorings = this.detectRefactoring(repository, revCommit.getId().getName());
		result.getChangeType().addAll(new TypeDiff().detectChange(version1, version2, refactorings, revCommit));
		result.getChangeMethod().addAll(new MethodDiff().detectChange(version1, version2, refactorings, revCommit));
		result.getChangeField().addAll(new FieldDiff().detectChange(version1, version2, refactorings, revCommit));
		return result;
	}

	@Override
	public Map<RefactoringType, List<SDRefactoring>> detectRefactoring(Repository repository, String commit) {
		RefactorProcessor refactoringDetector = new RefactoringProcessorImpl();
		return refactoringDetector.detectRefactoringAtCommit(repository, commit);
	}

}
