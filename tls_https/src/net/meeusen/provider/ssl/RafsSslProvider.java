package net.meeusen.provider.ssl;


import java.security.Provider;

public class RafsSslProvider extends Provider {

	private static final long serialVersionUID = 1L;

	public RafsSslProvider() {
		super("rafs", 6.66, "The info of provider rafs.");
		put("SSLContext.TLSv1.2", "customsslcontext.RafsSslContext");	
	}

}
