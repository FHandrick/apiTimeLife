package apidiff.analysis.description;

public class EnumConstantDescription extends TemplateDescription {

	public String remove(final String nameEnumConstant, final String path){
		return super.messageRemoveTemplate("Enum Constant", nameEnumConstant, "enum", path);
	}
}