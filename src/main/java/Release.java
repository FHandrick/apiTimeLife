import java.util.ArrayList;

public class Release {
	
	ArrayList<String> release = new ArrayList<String>();
	ArrayList<Comparation> comparations = new ArrayList<Comparation>();

	
	
	public ArrayList<Comparation> insert () {
		
		release.add("52b0902592e770b8116f80f2eab7a4048b589d7d");
		release.add("6de1c17dda8ffdb19431ffcadbce1836867a27a9");
		release.add("816e35d947172edc2a9be110f468f3080c142fdf");
		release.add("ae0a6aee62d49b6babf9bb49640a47a0c804a2ad");
		release.add("996763c72e128cd677fcd97d3fa74beb2c12124b");
		release.add("70b39c9a84327f522bcbe89d5a5fda65ebf630ac");
		release.add("47dc38fa0e7e4ad000f37f66474788d74dce8c93");
		release.add("37389a116a70cce57d7dcca190358e8d6eeedeb8");
		release.add("ef676b6f7bf6c66481f128732f7f376b1f369910");
		release.add("7107f91d9199401a19d4518d7c6b0f89e509d378");
		release.add("f6f530b18826c26347c4cbd8c459b880f3d39aa4");
		release.add("4f7f299340043738ff3a269724d4a9ab18e739d2");
		
		for (int i=0 ; i<release.size()-1 ; i++) {
				Comparation c = new Comparation(release.get(i),release.get(i+1));
				comparations.add(c);
		}
		return comparations;
	}
}
