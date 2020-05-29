package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

/*
 * source code: https://github.com/bit4woo/burp-api-common/blob/master/src/main/java/burp/Getter.java
 * author: bit4woo
 * github: https://github.com/bit4woo
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
	 * 获取header的字符串数组，是构造burp中请求需要的格式。
	 * return headers list
	 */
	public List<String> getHeaderList(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (null == messageInfo) return null;
		byte[] requestOrResponse = null;
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
		if (null == requestOrResponse) return null;
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

	/*
	 * 获取所有headers，当做一个string看待。
	 * 主要用于判断是否包含某个特殊字符串
	 * List<String> getHeaders 调用toString()方法，得到如下格式：[111111, 2222]
	 * 就能满足上面的场景了,废弃这个函数
	 */
	@Deprecated
	public String getHeaderString(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		List<String> headers =null;
		StringBuilder headerString = new StringBuilder();
		if(messageIsRequest) {
			IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
			headers = analyzeRequest.getHeaders();
		}else {
			IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
			headers = analyzeResponse.getHeaders();
		}

		for (String header : headers) {
			headerString.append(header);
		}

		return headerString.toString();
	}

	/*
	 * 获取header的map格式，key:value形式
	 * 这种方式可以用put函数轻松实现：如果有则update，如果无则add。
	 * ！！！注意：这个方法获取到的map，第一行将分割成形如 key = "GET", value= "/cps.gec/limit/information.html HTTP/1.1"
	 * 响应包则分割成形如：key =  "HTTP/1.1", value="200 OK"
	 */
	public LinkedHashMap<String,String> getHeaderMap(boolean messageIsRequest,IHttpRequestResponse messageInfo) {
		if (messageInfo == null) return null;
		List<String> headers=getHeaderList(messageIsRequest, messageInfo);
		return headerListToHeaderMap(headers);
	}

	/*
	 * use LinkedHashMap to keep headers in order
	 */
	public LinkedHashMap<String,String> getHeaderMap(boolean messageIsRequest,byte[] requestOrResponse) {
		if (requestOrResponse == null) return null;
		List<String> headers=getHeaderList(messageIsRequest, requestOrResponse);
		return headerListToHeaderMap(headers);
	}

	/*
	 * 仅该类内部调用
	 */
	private static LinkedHashMap<String, String> headerListToHeaderMap(List<String> headers) {
		LinkedHashMap<String,String> result = new LinkedHashMap<String, String>();
		if (null == headers) return null;
		for (String header : headers) {
			if (headers.indexOf(header) == 0) {
				String headerName = header.split(Header_firstLine_Spliter, 2)[0];//这里的limit=2 可以理解成分割成2份
				String headerValue = header.split(Header_firstLine_Spliter, 2)[1];
				result.put(headerName, headerValue);
			}else {
				//https://www.w3.org/Protocols/rfc2068/rfc2068-->4.2 Message Headers
				//https://blog.csdn.net/u012572955/article/details/50144535/
				//每个头域由一个域名，冒号（:）和域值三部分组成。域名是大小写无关的，域 值前可以添加任何数量的空格符
				try {
					String headerName = header.split(Header_Spliter, 2)[0].trim();//这里的limit=2 可以理解成分割成2份，否则referer可能别分成3份
					String headerValue = header.split(Header_Spliter, 2)[1].trim();
					result.put(headerName, headerValue);
				}catch (Exception e) {
					System.out.println("Wrong header -- "+header);
				}
			}
		}
		return result;
	}



	public List<String> headerMapToHeaderList(LinkedHashMap<String,String> Headers){
		List<String> result = new ArrayList<String>();
		for (Entry<String,String> header:Headers.entrySet()) {
			String key = header.getKey();
			String value = header.getValue();
			if (key.contains("HTTP/") || value.contains("HTTP/")) {//识别第一行
				String item = key+Header_firstLine_Spliter+value;
				result.add(0, item);
			}else {
				String item = key+Header_Connector+value;
				result.add(item);
			}
		}
		return result;
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,IHttpRequestResponse messageInfo, String headerName) {
		LinkedHashMap<String, String> headers = getHeaderMap(messageIsRequest,messageInfo);
		if (null ==headers || headerName ==null) return null;
		return headers.get(headerName.trim());
	}

	/*
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public String getHeaderValueOf(boolean messageIsRequest,byte[] requestOrResponse, String headerName) {
		LinkedHashMap<String, String> headers=getHeaderMap(messageIsRequest,requestOrResponse);
		if (null ==headers || headerName ==null) return null;
		return headers.get(headerName.trim());
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


	/*
	 * 注意，这里获取的URL包含了默认端口！
	 * this return value of url contains default port, 80 :443
	 * eg. http://bit4woo.com:80/
	 */
	@Deprecated
	public String getShortUrlStringWithDefaultPort(IHttpRequestResponse messageInfo) {
		URL fullUrl = getFullURLWithDefaultPort(messageInfo);
		if (fullUrl == null) {
			return null;
		}else {
			String shortUrl = fullUrl.toString().replace(fullUrl.getFile(), "/");
			return shortUrl;
		}
	}

	/*
	 *
	 * this return value of url will NOT contains default port, 80 :443
	 * eg.  https://www.baidu.com
	 */
	@Deprecated
	public String getShortUrlStringWithoutDefaultPort(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().toString()+"/"; //this result of this method doesn't contains default port
	}

	@Deprecated
	public String getFullUrlStringWithDefaultPort(IHttpRequestResponse messageInfo) {

		URL fullUrl = getFullURLWithDefaultPort(messageInfo);
		if (fullUrl == null) {
			return null;
		}else {
			return fullUrl.toString();
		}
	}

	/*
	 *
	 */
	@Deprecated
	public String getFullUrlStringWithoutDefaultPort(IHttpRequestResponse messageInfo) {
		URL fullUrl = getFullURLWithDefaultPort(messageInfo);
		if (fullUrl == null) {
			return null;
		}else {
			try {
				if (fullUrl.getProtocol().equalsIgnoreCase("https") && fullUrl.getPort() == 443) {
					return new URL(fullUrl.toString().replaceFirst(":443/", ":/")).toString();
				}
				if (fullUrl.getProtocol().equalsIgnoreCase("http") && fullUrl.getPort() == 80) {
					return new URL(fullUrl.toString().replaceFirst(":80/", ":/")).toString();
				}
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}
			return null;
		}
	}

	/*
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
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

	@Deprecated
	private final URL getFullURLWithDefaultPort(IHttpRequestResponse messageInfo){
		return getFullURL(messageInfo);
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
	
	public IHttpRequestResponse updateBody(boolean isRequest,IHttpRequestResponse messageInfo,byte[] newBody) {
		if (isRequest) {
			List<String> Headers = getHeaderList(isRequest, messageInfo);
			byte[] request = helpers.buildHttpMessage(Headers,newBody);
			messageInfo.setRequest(request);
		}else {
			List<String> Headers = getHeaderList(isRequest, messageInfo);
			byte[] response = helpers.buildHttpMessage(Headers,newBody);
			messageInfo.setResponse(response);
		}
		return messageInfo;
	}
	
	public byte[] updateBody(boolean isRequest,byte[] requestOrResponse,byte[] newBody) {
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
		byte[] byte_header = Arrays.copyOfRange(requestOrResponse,0, bodyOffset);
		byte[] byte_header
		byte[] byte_body = Arrays.copyOfRange(requestOrResponse, bodyOffset, requestOrResponse.length);//not length-1
		//String body = new String(byte_body); //byte[] to String
		return byte_body;
	}
	
	/*
	 * put 操作，类似于Map中的put，如果存在就覆盖，不存在就新增
	 */
	public IHttpRequestResponse putHeader(boolean isRequest,IHttpRequestResponse messageInfo,String headerKey, String headerValue) {
		LinkedHashMap<String, String> Headers = getHeaderMap(isRequest, messageInfo);
		Headers.put(headerKey, headerKey);
		List<String> newHeaders = headerMapToHeaderList(Headers);
		byte[] body = getBody(isRequest,messageInfo);
		
		if (isRequest) {
			byte[] request = helpers.buildHttpMessage(newHeaders,body);
			messageInfo.setRequest(request);
		}else {
			byte[] response = helpers.buildHttpMessage(newHeaders,body);
			messageInfo.setResponse(response);
		}
		return messageInfo;
	}
	
	public byte[] putHeader(boolean isRequest,byte[] requestOrResponse,String headerKey, String headerValue) {
		LinkedHashMap<String, String> Headers = getHeaderMap(isRequest, requestOrResponse);
		Headers.put(headerKey, headerKey);
		List<String> newHeaders = headerMapToHeaderList(Headers);
		byte[] body = getBody(isRequest,requestOrResponse);
		
		return helpers.buildHttpMessage(newHeaders,body);
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
		String a= "xxxxx%s%bxxxxxxx";
		System.out.println(String.format(a, "111"));
	}
}
