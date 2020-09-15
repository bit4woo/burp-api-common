package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/*
 * source code: https://github.com/bit4woo/burp-api-common/blob/master/src/main/java/burp/HelperPlus.java
 * author: bit4woo
 * github: https://github.com/bit4woo
 * 
 * getHeaderStr
 * getHeaderList
 * getHeader
 * getHeaderValueOf
 * 
 * addOrUpdateHeaderList
 * removeHeaderList
 * 
 * 
 * getBody
 * 
 * shorturl
 * url
 * protocol
 * host
 * port
 * Paras
 * 
 * method
 * statusCode
 * 
 * 
 */

public class HelperPlus {
	private static IExtensionHelpers helpers;
	private final static String Header_Spliter = ":";
	private final static String Header_Connector = ": ";//contains space
	private final static String Header_firstLine_Spliter = " ";

	public HelperPlus(IExtensionHelpers helpers) {
		HelperPlus.helpers = helpers;
	}
	/*
	 * 返回HTTP请求或响应的整个header头部分，于body相对应
	 */
	public String getHeadersAsStr(boolean isRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null){
			return null;
		}
		int bodyOffset = -1;
		if(isRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			bodyOffset = analyzeRequest.getBodyOffset();
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			bodyOffset = analyzeResponse.getBodyOffset();
		}
		byte[] byte_header = Arrays.copyOfRange(requestOrResponse,0,bodyOffset);//not length-1
		return new String(byte_header);
	}

	/*
	 * 返回HTTP请求或响应的整个header头部分，于body相对应
	 */
	public String getHeadersAsStr(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (messageInfo == null){
			return null;
		}
		byte[] requestOrResponse = null;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeadersAsStr(messageIsRequest, requestOrResponse);
	}

	/*
	 * 获取header的字符串数组，是构造burp中请求需要的格式。
	 * return headers list
	 */
	public List<String> getHeaderList(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (null == messageInfo) {
			return new ArrayList<>();
		}
		byte[] requestOrResponse;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeaderList(messageIsRequest,requestOrResponse);
	}

	/*
	 * 获取请求包或者响应包中的header List
	 */
	public List<String> getHeaderList(boolean IsRequest,byte[] requestOrResponse) {
		if (null == requestOrResponse) {
			return new ArrayList<>();
		}
		if(IsRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			List<String> headers = analyzeRequest.getHeaders();
			return headers;
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			List<String> headers = analyzeResponse.getHeaders();
			return headers;
		}
	}

	public static List<String> addOrUpdateHeader(List<String> headers,String headerName,String headerValue) {
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						int index = headers.indexOf(header);
						headers.remove(header);
						headers.add(index, headerName+Header_Connector+headerValue);
						return headers;
					}
				}catch (Exception e) {

				}
			}
		}
		headers.add(headerName+Header_Connector+headerValue);
		return headers;
	}

	public static List<String> removeHeader(List<String> headers,String headerNameOrHeader) {
		Iterator<String> it = headers.iterator();
		while(it.hasNext()) {
			String header = it.next();
			String headerName = header.split(Header_Spliter, 2)[0].trim();
			if (header.toLowerCase().startsWith(headerNameOrHeader.toLowerCase().trim())
					&& headerNameOrHeader.length() >= headerName.length()) {
				it.remove();
			}
		}
		return headers;
	}

	public static String getHeaderLine(List<String> headers,String headerName) {
		if (null ==headers || headerName ==null) return null;
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return header;
					}
				}catch (Exception e) {

				}
			}
		}
		return null;
	}

	public String getHeaderLine(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderLine(headers,headerName);
	}

	public String getHeader(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderLine(headers,headerName);
	}

	public String getHeaderValueOf(List<String> headers,String headerName) {
		if (null ==headers || headerName ==null) return null;
		for (String header:headers) {
			if (header.contains(":")) {
				try {
					String headerNameOrigin = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					String headerValue = header.split(Header_Spliter, 2)[1].trim();
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return headerValue;
					}
				}catch (Exception e) {

				}
			}
		}
		return null;
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest,messageInfo);
		return getHeaderValueOf(headers,headerName);
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		List<String> headers=getHeaderList(messageIsRequest,requestOrResponse);
		return getHeaderValueOf(headers,headerName);
	}


	public byte[] getBody(boolean isRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null){
			return null;
		}
		int bodyOffset = -1;
		if(isRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(requestOrResponse);
			bodyOffset = analyzeRequest.getBodyOffset();
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(requestOrResponse);
			bodyOffset = analyzeResponse.getBodyOffset();
		}
		byte[] byte_body = Arrays.copyOfRange(requestOrResponse, bodyOffset, requestOrResponse.length);//not length-1
		//String body = new String(byte_body); //byte[] to String
		return byte_body;
	}

	public byte[] getBody(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (messageInfo == null){
			return null;
		}
		byte[] requestOrResponse = null;
		if(messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		}else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getBody(messageIsRequest, requestOrResponse);
	}

	/*
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. 
	 * the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * result example:
	 *  
	 * eg. http://bit4woo.com:80/ 包含默认端口和默认path(/)
	 */
	public URL getShortURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		String shortUrlString = messageInfo.getHttpService().toString();//http://www.baidu.com
		shortUrlString = formateURLString(shortUrlString);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * 
	 * 这个函数的返回结果转换成字符串是包含了默认端口的。
	 * http://bit4woo.com:80/test.html#123
	 */
	public final URL getFullURL(IHttpRequestResponse messageInfo){
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getUrl();
	}


	/*
	 * to let url String contains default port(80\443) and default path(/)
	 * 
	 * from: http://bit4woo.com
	 * to  : http://bit4woo.com:80/
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

	public String getHost(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getHost();
	}

	public String getProtocol(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getProtocol();
	}

	public int getPort(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getPort();
	}

	public short getStatusCode(IHttpRequestResponse messageInfo) {
		if (messageInfo == null || messageInfo.getResponse() == null) {
			return -1;
		}
		IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse());
		return analyzedResponse.getStatusCode();
	}

	public short getStatusCode(byte[] response) {
		if (response == null) {
			return -1;
		}
		try {
			IResponseInfo analyzedResponse = helpers.analyzeResponse(response);
			return analyzedResponse.getStatusCode();
		} catch (Exception e) {
			return -1;
		}
	}

	public List<IParameter> getParas(IHttpRequestResponse messageInfo){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getParameters();
	}

	public List<IParameter> getParas(byte[] request){
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return analyzeRequest.getParameters();
	}

	public String getMethod(IHttpRequestResponse messageInfo){
		if (messageInfo == null || messageInfo.getRequest() == null) {
			return null;
		}
		IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo.getRequest());
		return analyzedRequest.getMethod();
	}

	public String getMethod(byte[] request){
		if (request == null) {
			return null;
		}
		try {
			IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
			return analyzedRequest.getMethod();
		} catch (Exception e) {
			return null;
		}
	}

	public String getHTTPBasicCredentials(IHttpRequestResponse messageInfo) throws Exception{
		String authHeader  = getHeaderValueOf(true, messageInfo, "Authorization").trim();
		String[] parts = authHeader.split("\\s");

		if (parts.length != 2)
			throw new Exception("Wrong number of HTTP Authorization header parts");

		if (!parts[0].equalsIgnoreCase("Basic"))
			throw new Exception("HTTP authentication must be Basic");

		return parts[1];
	}

	public static void main(String args[]) {
		List<String> headerList = new ArrayList<String>();
		headerList.add("User-Agent: sssss");
		headerList.add("Use: sssss");
		headerList.add("User: sssss");
		headerList.add("Agent: sssss");
		List<String> newHeader = removeHeader(headerList,"Use");
		System.out.println(newHeader.toString());
		newHeader = addOrUpdateHeader(headerList,"Use1","xxxx");
		System.out.println(newHeader.toString());
	}
}
