package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTextArea;

public class JavaGUIUtils {
	public static List<String> getLinesFromTextArea(JTextArea textarea){
		return textToLines(textarea.getText());
	}

	/**
	 * 换行符的可能性有三种，都必须考虑到
	 * @param input
	 * @return
	 */
	public static List<String> textToLines(String input){
		String[] lines = input.split("(\r\n|\r|\n)", -1);
		List<String> result = new ArrayList<String>();
		for(String line: lines) {
			line = line.trim();
			if (!line.equalsIgnoreCase("")) {
				result.add(line.trim());
			}
		}
		return result;
	}
}
