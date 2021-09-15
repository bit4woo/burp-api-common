package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTextArea;

public class JavaGUIUtils {
	public static List<String> getLinesFromTextArea(JTextArea textarea){
		//user input maybe use "\n" in windows, so the System.lineSeparator() not always works fine!
		String[] lines = textarea.getText().replaceAll("\r\n", "\n").split("\n");
		List<String> result = new ArrayList<String>();
		for(String line: lines) {
			line = line.trim();
			if (line!="") {
				result.add(line.trim());
			}
		}
		return result;
	}
}
