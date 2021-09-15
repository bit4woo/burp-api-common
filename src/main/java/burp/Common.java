package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 常用格式校验
 * 各种按照正则进行提取
 * 数据格式化
 * 类型转换
 */
public class Common {
	
	public static final String URL_Regex = "(?:\"|')"
			+ "("
			+ "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})"
			+ "|"
			+ "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})"
			+ "|"
			+ "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))"
			+ "|"
			+ "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))"
			+ ")"
			+ "(?:\"|')";
	
    private static final String IP_ADDRESS_STRING =
            "((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\\.(25[0-5]|2[0-4]"
            + "[0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]"
            + "[0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}"
            + "|[1-9][0-9]|[0-9]))";
	
	//域名校验和域名提取还是要区分对待
		//domain.DomainProducer.grepDomain(String)是提取域名的，正则中包含了*号
		public static boolean isValidDomain(String domain) {
			if (null == domain) {
				return false;
			}
			final String DOMAIN_NAME_PATTERN = "([A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";
			Pattern pDomainNameOnly = Pattern.compile(DOMAIN_NAME_PATTERN);
			Matcher matcher = pDomainNameOnly.matcher(domain);
			return matcher.matches();
		}

		//校验字符串是否是一个合格的IP地址
		public static boolean isValidIP (String ip) {
			try {
				if ( ip == null || ip.isEmpty() ) {
					return false;
				}

				String[] parts = ip.split( "\\." );
				if ( parts.length != 4 ) {
					return false;
				}

				for ( String s : parts ) {
					int i = Integer.parseInt( s );
					if ( (i < 0) || (i > 255) ) {
						return false;
					}
				}
				if ( ip.endsWith(".") ) {
					return false;
				}

				return true;
			} catch (NumberFormatException nfe) {
				return false;
			}
		}
		
		public static boolean isPrivateIPv4(String ipAddress) {
	        try {
	            String[] ipAddressArray = ipAddress.split("\\.");
	            int[] ipParts = new int[ipAddressArray.length];
	            for (int i = 0; i < ipAddressArray.length; i++) {
	                ipParts[i] = Integer.parseInt(ipAddressArray[i].trim());
	            }
	            
	            switch (ipParts[0]) {
	                case 10:
	                case 127:
	                    return true;
	                case 172:
	                    return (ipParts[1] >= 16) && (ipParts[1] < 32);
	                case 192:
	                    return (ipParts[1] == 168);
	                case 169:
	                    return (ipParts[1] == 254);
	            }
	        } catch (Exception ex) {
	        }
	        
	        return false;
	    }

	    public static boolean isPrivateIPv6(String ipAddress) {
	        boolean isPrivateIPv6 = false;
	        String[] ipParts = ipAddress.trim().split(":");
	        if (ipParts.length > 0) {
	            String firstBlock = ipParts[0];
	            String prefix = firstBlock.substring(0, 2);
	            
	            if (firstBlock.equalsIgnoreCase("fe80")
	                    || firstBlock.equalsIgnoreCase("100")
	                    || ((prefix.equalsIgnoreCase("fc") && firstBlock.length() >= 4))
	                    || ((prefix.equalsIgnoreCase("fd") && firstBlock.length() >= 4))) {
	                isPrivateIPv6 = true;
	            }
	        }
	        return isPrivateIPv6;
	    }
	    
		public static ArrayList<String> regexFind(String regex,String content) {
			ArrayList<String> result = new ArrayList<String>();
			Pattern pRegex = Pattern.compile(regex);
			Matcher matcher = pRegex.matcher(content);
			while (matcher.find()) {//多次查找
				result.add(matcher.group());
			}
			return result;
		}
	    
		public static Set<String> grepDomain(String httpResponse) {
			httpResponse = httpResponse.toLowerCase();
			//httpResponse = cleanResponse(httpResponse);
			Set<String> domains = new HashSet<>();
			//"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
			final String DOMAIN_NAME_PATTERN = "([A-Za-z0-9-*]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";
			//加*号是为了匹配 类似 *.baidu.com的这种域名记录。

			String[] lines = httpResponse.split("\r\n");

			for (String line:lines) {//分行进行提取，似乎可以提高成功率？
				Pattern pDomainNameOnly = Pattern.compile(DOMAIN_NAME_PATTERN);
				Matcher matcher = pDomainNameOnly.matcher(line);
				while (matcher.find()) {//多次查找
					String tmpDomain = matcher.group();
					if (tmpDomain.startsWith("*.")) {
						tmpDomain = tmpDomain.replaceFirst("\\*\\.","");//第一个参数是正则
					}
					domains.add(tmpDomain);
				}
			}
			return domains;
		}

		//https://stackoverflow.com/questions/163360/regular-expression-to-match-urls-in-java
		//https://github.com/aosp-mirror/platform_frameworks_base/blob/master/core/java/android/util/Patterns.java
		public static List<String> grepURL(String httpResponse) {
			httpResponse = httpResponse.toLowerCase();
			Set<String> URLs = new HashSet<>();

			String[] lines = httpResponse.split("\r\n");

			Pattern pt = Pattern.compile(URL_Regex);
			for (String line:lines) {//分行进行提取，似乎可以提高成功率？PATH_AND_QUERY
				Matcher matcher = pt.matcher(line);
				while (matcher.find()) {//多次查找
					String url = matcher.group();
					URLs.add(url);
				}
			}

			List<String> tmplist= new ArrayList<>(URLs);
			return tmplist;
		}

		public static List<String> grepIP(String httpResponse) {
			Set<String> IPSet = new HashSet<>();
			String[] lines = httpResponse.split("\r\n");

			Pattern pt = Pattern.compile(IP_ADDRESS_STRING);
			for (String line:lines) {
				Matcher matcher = pt.matcher(line);
				while (matcher.find()) {//多次查找
					String tmpIP = matcher.group();
					IPSet.add(tmpIP);
				}
			}
			
			List<String> tmplist= new ArrayList<>(IPSet);
			Collections.sort(tmplist);		
			return tmplist;
		}
		
		public static List<String> grepIPAndPort(String httpResponse) {
			Set<String> IPSet = new HashSet<>();
			String[] lines = httpResponse.split("\r\n");

			for (String line:lines) {
				String pattern = "\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d{1,5})?";
				Pattern pt = Pattern.compile(pattern);
				Matcher matcher = pt.matcher(line);
				while (matcher.find()) {//多次查找
					String tmpIP = matcher.group();
					IPSet.add(tmpIP);
				}
			}
			
			List<String> tmplist= new ArrayList<>(IPSet);
			Collections.sort(tmplist);		
			return tmplist;
		}
		
		@Deprecated //从burp的Email addresses disclosed这个issue中提取，废弃这个
		public static Set<String> grepEmail(String httpResponse) {
			Set<String> Emails = new HashSet<>();
			final String REGEX_EMAIL = "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+";

			Pattern pDomainNameOnly = Pattern.compile(REGEX_EMAIL);
			Matcher matcher = pDomainNameOnly.matcher(httpResponse);
			while (matcher.find()) {//多次查找
				Emails.add(matcher.group());
				System.out.println(matcher.group());
			}

			return Emails;
		}
		
		/**
	     * 获取随机字符串
	     * @param length
	     * @return
	     */
	    public static String getRandomString(int length) {
	        String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	        Random random = new Random();
	        char[] text = new char[length];
	        for (int i = 0; i < length; i++) {
	            text[i] = str.charAt(random.nextInt(str.length()));
	        }
	        return new String(text);
	    }
	    
	    public static String getSystemCharSet() {
			return Charset.defaultCharset().toString();

			//System.out.println(System.getProperty("file.encoding"));
		}

	    public static Long getTimestamp(Date date){  
	        if (null == date) {  
	            return (long) 0;  
	        }
	        return date.getTime();
	    }
	    
	    /*
	     * 	标准的时间格式要求 2020-12-11 12:00:00
	     * 	效果如同 https://tool.lu/timestamp/
	     */
	    public static Long getTimestamp(String date) throws Exception{  
	        if (null == date) {  
	            return (long) 0;
	        }  
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			return dateFormat.parse(date).getTime();
	    }
	    
		public static String timeStr() {
			SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式  
			String time = df.format(new Date());// new Date()为获取当前系统时间  
			return time;
		}
		
		public static String timePlusOrSub(long sec) {
			SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式  
			String time = df.format(new Date(new Date().getTime() + sec * 1000));// new Date()为获取当前系统时间  
			return time;
		}

		/**
		 * 字符串转unicode
		 *
		 * @param str
		 * @return
		 */
		public static String stringToUnicode(String str) {
			StringBuffer sb = new StringBuffer();
			char[] c = str.toCharArray();
			for (int i = 0; i < c.length; i++) {
				sb.append("\\u" + Integer.toHexString(c[i]));
			}
			return sb.toString();
		}

		/**
		 * unicode转字符串
		 *
		 * @param unicode
		 * @return
		 */
		public static String unicodeToString(String unicode) {
			StringBuffer sb = new StringBuffer();
			String[] hex = unicode.split("\\\\u");
			for (int i = 1; i < hex.length; i++) {
				int index = Integer.parseInt(hex[i], 16);
				sb.append((char) index);
			}
			return sb.toString();
		}
		
	    /**
	     * 将10进制转换为16进制
	     * @param decimal 10进制
	     * @return 16进制
	     */
	    public static String decimalToHex(int decimal) {
	        String hex = Integer.toHexString(decimal);
	        return  hex.toUpperCase();
	    }
	    
		public static boolean isNumeric(String str){
			for(int i=str.length();--i>=0;){
				int chr=str.charAt(i);
				if(chr<48 || chr>57) {
					return false;
				}
			}
			return true;
		}
		
		/*
		 *将形如 https://www.runoob.com的URL统一转换为
		 * https://www.runoob.com:443/
		 * 
		 * 因为末尾的斜杠，影响URL类的equals的结果。
		 * 而默认端口影响String格式的对比结果。
		 */

		public static String formateURLString(String urlString) {
			try {
				//urlString = "https://www.runoob.com";
				URL url = new URL(urlString);
				String host = url.getHost();
				int port = url.getPort();
				String path = url.getPath();

				if (port == -1) {
					String newHost = url.getHost()+":"+url.getDefaultPort();
					urlString = urlString.replace(host, newHost);
				}

				if (path.equals("")) {
					urlString = urlString+"/";
				}
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}
			return urlString;
		}
		
		/**
		 * baseUrl格式：https://www.runoob.com
		 * @param urlString
		 * @return
		 */
		public static String getBaseUrl(String urlString) {
			try {
				//urlString = "https://www.runoob.com";
				URL url = new URL(urlString);
				String procotol = url.getProtocol();
				String host = url.getHost();
				int port = url.getPort();

				if (port == -1) {
					port = url.getDefaultPort();
				}
				return procotol+"://"+host+port;
			} catch (MalformedURLException e) {
				e.printStackTrace();
				return urlString;
			}
		}
		

		public static List<String> removePrefixAndSuffix(List<String> input,String Prefix,String Suffix) {
			ArrayList<String> result = new ArrayList<String>();
			if (Prefix == null && Suffix == null) {
				return result;
			} else {
				if (Prefix == null) {
					Prefix = "";
				}

				if (Suffix == null) {
					Suffix = "";
				}

				List<String> content = input;
				for (String item:content) {
					if (item.startsWith(Prefix)) {
						//https://stackoverflow.com/questions/17225107/convert-java-string-to-string-compatible-with-a-regex-in-replaceall
						String tmp = Pattern.quote(Prefix);//自动实现正则转义
						item = item.replaceFirst(tmp, "");
					}
					if (item.endsWith(Suffix)) {
						String tmp = Pattern.quote(reverse(Suffix));//自动实现正则转义
						item = reverse(item).replaceFirst(tmp, "");
						item = reverse(item);
					}
					result.add(item); 
				}
				return result;
			}
		}
		
		public static String reverse(String str) {
			if (str == null) {
				return null;
			}
			return new StringBuffer(str).reverse().toString();
		}
	    
		/**
		 * 拼接多个byte[]数组的方法
		 * @param arrays
		 * @return
		 */
		public static byte[] join(byte[]... arrays)
		{
			int len = 0;
			for (byte[] arr : arrays)
			{
				len += arr.length;//计算多个数组的长度总和
			}

			byte[] result = new byte[len];
			int idx = 0;

			for (byte[] arr : arrays)
			{
				for (byte b : arr)
				{
					result[idx++] = b;
				}
			}

			return result;
		}
	    public static void main(String[] args) {
	        // test IPv4
	        String ipv4Address = "127.56.87.4";

	        if (isPrivateIPv4(ipv4Address)) {
	            System.out.println("This is a private IPv4");
	        }
	        
	        // test IPv6 
	        String ipv6Address = "fe80:db8:a0b:12f0::1";

	        if (isPrivateIPv6(ipv6Address)) {
	            System.out.println("This is a private IPv6");
	        }
	    }
}
