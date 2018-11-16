package apiTimeLIfe.util;


public class Comparison {
	public String commitBegin = "";
	public String commitFinal = "";
	public Comparison(String commitBegin, String coomitFinal) {
		super();
		this.setCommitBegin(commitBegin);
		this.setCommitFinal(coomitFinal);
	}
	public String getCommitBegin() {
		return commitBegin;
	}
	public void setCommitBegin(String commitBegin) {
		this.commitBegin = commitBegin;
	}
	public String getCommitFinal() {
		return commitFinal;
	}
	public void setCommitFinal(String commitFinal) {
		this.commitFinal = commitFinal;
	}
}
