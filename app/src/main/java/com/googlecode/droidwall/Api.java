/**
 * Contains shared programming interfaces.
 * All iptables "communication" is handled by this class.
 * 
 * Copyright (C) 2009-2011  Rodrigo Zechin Rosauro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Rodrigo Zechin Rosauro
 * @version 1.0
 */

package com.googlecode.droidwall;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.Toast;



/**
 * Contains shared programming interfaces.
 * All iptables "communication" is handled by this class.
 */
public final class Api {
	private static final String TAG = "Api";
	/** application version string */
	public static final String VERSION = "1.5.7";
	/** special application UID used to indicate "any application" */
	public static final int SPECIAL_UID_ANY	= -10;
	/** special application UID used to indicate the Linux Kernel */
	public static final int SPECIAL_UID_KERNEL	= -11;
	/** root script filename */
	private static final String SCRIPT_FILE = "droidwall.sh";
	
	// Preferences
	public static final String PREFS_NAME 			= "DroidWallPrefs";
	public static final String PREF_3G_UIDS			= "AllowedUids3G";
	public static final String PREF_WIFI_UIDS		= "AllowedUidsWifi";
	public static final String PREF_PASSWORD 		= "Password";
	public static final String PREF_CUSTOMSCRIPT 	= "CustomScript";
	public static final String PREF_CUSTOMSCRIPT2 	= "CustomScript2"; // Executed on shutdown
	public static final String PREF_MODE 			= "BlockMode";
	public static final String PREF_ENABLED			= "Enabled";
	public static final String PREF_LOGENABLED		= "LogEnabled";
	public static final String PREF_CAP_UIDS		= "CapUids";
	public static final String PREF_RAWCAP          = "RawCapEnabled";
	public static final String PREF_SSLCAP          = "SslCapEnabled";
	public static final String PREF_AUTOCAP         = "AutoCapEnabled";
	public static final String PREF_AUTOCAP_CURRENT = "AutoCapCurrent";
	// Modes
	public static final String MODE_WHITELIST = "whitelist";
	public static final String MODE_BLACKLIST = "blacklist";
	// Messages
	public static final String STATUS_CHANGED_MSG 	= "com.googlecode.droidwall.intent.action.STATUS_CHANGED";
	public static final String TOGGLE_REQUEST_MSG	= "com.googlecode.droidwall.intent.action.TOGGLE_REQUEST";
	public static final String CUSTOM_SCRIPT_MSG	= "com.googlecode.droidwall.intent.action.CUSTOM_SCRIPT";
	// Message extras (parameters)
	public static final String STATUS_EXTRA			= "com.googlecode.droidwall.intent.extra.STATUS";
	public static final String SCRIPT_EXTRA			= "com.googlecode.droidwall.intent.extra.SCRIPT";
	public static final String SCRIPT2_EXTRA		= "com.googlecode.droidwall.intent.extra.SCRIPT2";
	// Binary file name
	public static final String BIN_BUSYBOX_ARM      = "busybox_armv6l";
	public static final String BIN_IPTABLES_ARM     = "iptables_armv5";
	public static final String BIN_SSLSPLIT_ARM     = "sslsplit_armv7hf";
	public static final String BIN_TCPDUMP_ARM      = "tcpdump_armv7hf";
	public static final String BIN_BUSYBOX_X86      = "busybox_x86";
	public static final String BIN_IPTABLES_X86     = "iptables_x86";
	public static final String BIN_SSLSPLIT_X86     = "sslsplit_x86";
	public static final String BIN_TCPDUMP_X86      = "tcpdump_x86";
	public static String BIN_BUSYBOX                = BIN_BUSYBOX_ARM;
	public static String BIN_IPTABLES               = BIN_IPTABLES_ARM;
	public static String BIN_SSLSPLIT               = BIN_SSLSPLIT_ARM;
	public static String BIN_TCPDUMP                = BIN_TCPDUMP_ARM;
	// Capture directory
	public static final String DIR_CAPTURE          = "/sdcard/capture";
	// default ssl port
	public static final String DEF_SSL_PORT         = "443";

	
	// Cached applications
	public static DroidApp applications[] = null;
	// Do we have root access?
	private static boolean hasroot = false;

	public static void initArch(String abi){
		if (abi.contains("x86"))
		{
			BIN_BUSYBOX    = BIN_BUSYBOX_X86;
			BIN_IPTABLES   = BIN_IPTABLES_X86;
			BIN_SSLSPLIT   = BIN_SSLSPLIT_X86;
			BIN_TCPDUMP    = BIN_TCPDUMP_X86;
		}
	}

    /**
     * Display a simple alert box
     * @param ctx context
     * @param msg message
     */
	public static void alert(Context ctx, CharSequence msg) {
    	if (ctx != null) {
        	new AlertDialog.Builder(ctx)
        	.setNeutralButton(android.R.string.ok, null)
        	.setMessage(msg)
        	.show();
    	}
    }
	/**
	 * Create the generic shell script header used to determine which iptables binary to use.
	 * @param ctx context
	 * @return script header
	 */
	private static String scriptHeader(Context ctx) {
		final String dir = ctx.getDir("bin",0).getAbsolutePath();
		final String myiptables = dir + "/" + BIN_IPTABLES;
        final String mysslsplit = dir + "/" + BIN_SSLSPLIT;
        final String mytcpdump = dir + "/" + BIN_TCPDUMP;
		return "" +
			"IPTABLES=iptables\n" +
			"BUSYBOX=busybox\n" +
			"GREP=grep\n" +
			"ECHO=echo\n" +
			"TCPDUMP=" + mytcpdump + "\n" +
			"SSLSPLIT=" + mysslsplit + "\n" +
			"BUSYBOX_ARCHSPEC=" + BIN_BUSYBOX + "\n" +
			"# Try to find busybox\n" +
			"if " + dir + "/$BUSYBOX_ARCHSPEC --help >/dev/null 2>/dev/null ; then\n" +
			"	BUSYBOX="+dir+"/$BUSYBOX_ARCHSPEC\n" +
			"	GREP=\"$BUSYBOX grep\"\n" +
			"	ECHO=\"$BUSYBOX echo\"\n" +
			"elif busybox --help >/dev/null 2>/dev/null ; then\n" +
			"	BUSYBOX=busybox\n" +
			"elif /system/xbin/busybox --help >/dev/null 2>/dev/null ; then\n" +
			"	BUSYBOX=/system/xbin/busybox\n" +
			"elif /system/bin/busybox --help >/dev/null 2>/dev/null ; then\n" +
			"	BUSYBOX=/system/bin/busybox\n" +
			"fi\n" +
			"# Try to find grep\n" +
			"if ! $ECHO 1 | $GREP -q 1 >/dev/null 2>/dev/null ; then\n" +
			"	if $ECHO 1 | $BUSYBOX grep -q 1 >/dev/null 2>/dev/null ; then\n" +
			"		GREP=\"$BUSYBOX grep\"\n" +
			"	fi\n" +
			"	# Grep is absolutely required\n" +
			"	if ! $ECHO 1 | $GREP -q 1 >/dev/null 2>/dev/null ; then\n" +
			"		$ECHO The grep command is required. DroidWall will not work.\n" +
			"		exit 1\n" +
			"	fi\n" +
			"fi\n" +
			"# Try to find iptables\n" +
			"if " + myiptables + " --version >/dev/null 2>/dev/null ; then\n" +
			"	IPTABLES="+myiptables+"\n" +
			"fi\n" +
            "# Try to find tcpdump\n" +
            "if ! $TCPDUMP -h >/dev/null 2>/dev/null ; then \n" +
            "   $ECHO The tcpdump command is required. Capture will not work.\n" +
            "   exit 1\n" +
			"fi\n" +
            "# Try to find sslsplit\n" +
            "if ! $SSLSPLIT -V >/dev/null 2>/dev/null ; then \n" +
            "   $ECHO The sslsplit command is required. Capture will not work.\n" +
            "   exit 1\n" +
			"fi\n" +
			"";
	}
	/**
	 * Copies a raw resource file, given its ID to the given location
	 * @param ctx context
	 * @param resid resource id
	 * @param file destination file
	 * @param mode file permissions (E.g.: "755")
	 * @throws IOException on error
	 * @throws InterruptedException when interrupted
	 */
	private static void copyRawFile(Context ctx, int resid, File file, String mode) throws IOException, InterruptedException
	{
		final String abspath = file.getAbsolutePath();
		// Write the iptables binary
		final FileOutputStream out = new FileOutputStream(file);
		final InputStream is = ctx.getResources().openRawResource(resid);
		byte buf[] = new byte[1024];
		int len;
		while ((len = is.read(buf)) > 0) {
			out.write(buf, 0, len);
		}
		out.close();
		is.close();
		// Change the permissions
		Runtime.getRuntime().exec("chmod "+mode+" "+abspath).waitFor();
	}
    /**
     * Purge and re-add all rules (internal implementation).
     * @param ctx application context (mandatory)
     * @param uidsWifi list of selected UIDs for WIFI to allow or disallow (depending on the working mode)
     * @param uids3g list of selected UIDs for 2G/3G to allow or disallow (depending on the working mode)
	 * @param sslPort possible SSL server port
     * @param showErrors indicates if errors should be alerted
     */
	private static boolean applyIptablesRulesImpl(Context ctx, List<Integer> uidsWifi, List<Integer> uids3g, List<Integer> uidsCap, List<String> sslPort, boolean showErrors) {
		if (ctx == null) {
			return false;
		}
		assertBinaries(ctx, showErrors);
		final String ITFS_WIFI[] = {"tiwlan+", "wlan+", "eth+", "ra+"};
		final String ITFS_3G[] = {"rmnet+","pdp+","ppp+","uwbr+","wimax+","vsnet+","ccmni+","usb+"};
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		final boolean whitelist = prefs.getString(PREF_MODE, MODE_WHITELIST).equals(MODE_WHITELIST);
		final boolean blacklist = !whitelist;
		final boolean logenabled = ctx.getSharedPreferences(PREFS_NAME, 0).getBoolean(PREF_LOGENABLED, false);
		final String customScript = ctx.getSharedPreferences(Api.PREFS_NAME, 0).getString(Api.PREF_CUSTOMSCRIPT, "");

    	final StringBuilder script = new StringBuilder();
		try {
			int code;
			script.append(scriptHeader(ctx));
			script.append("" +
				"$IPTABLES --version || exit 1\n" +
				"# Create the droidwall chains if necessary\n" +
				"$IPTABLES -L droidwall >/dev/null 2>/dev/null || $IPTABLES --new droidwall || exit 2\n" +
				"$IPTABLES -L droidwall-3g >/dev/null 2>/dev/null || $IPTABLES --new droidwall-3g || exit 3\n" +
				"$IPTABLES -L droidwall-wifi >/dev/null 2>/dev/null || $IPTABLES --new droidwall-wifi || exit 4\n" +
				"$IPTABLES -L droidwall-reject >/dev/null 2>/dev/null || $IPTABLES --new droidwall-reject || exit 5\n" +
				"# Add droidwall chain to OUTPUT chain if necessary\n" +
				"$IPTABLES -L OUTPUT | $GREP -q droidwall || $IPTABLES -A OUTPUT -j droidwall || exit 6\n" +
				"# Flush existing rules\n" +
				"$IPTABLES -F droidwall || exit 7\n" +
				"$IPTABLES -F droidwall-3g || exit 8\n" +
				"$IPTABLES -F droidwall-wifi || exit 9\n" +
				"$IPTABLES -F droidwall-reject || exit 10\n" +
				"# Create rules for capture and flush existed rules\n" +
				"$IPTABLES -t nat -L capture >/dev/null 2>/dev/null || $IPTABLES -t nat --new capture || exit 11\n" +
				"$IPTABLES -t nat -D OUTPUT -j capture >/dev/null 2>/dev/null\n" +
				"$IPTABLES -t nat -A OUTPUT -j capture >/dev/null 2>/dev/null || exit 13\n" +
				"$IPTABLES -t nat -F capture >/dev/null 2>/dev/null || exit 14\n" +
			"");
			// Check if logging is enabled
			if (logenabled) {
				script.append("" +
					"# Create the log and reject rules (ignore errors on the LOG target just in case it is not available)\n" +
					"$IPTABLES -A droidwall-reject -j LOG --log-prefix \"[DROIDWALL] \" --log-uid\n" +
					"$IPTABLES -A droidwall-reject -j REJECT || exit 11\n" +
				"");
			} else {
				script.append("" +
					"# Create the reject rule (log disabled)\n" +
					"$IPTABLES -A droidwall-reject -j REJECT || exit 11\n" +
				"");
			}
			if (customScript.length() > 0) {
				script.append("\n# BEGIN OF CUSTOM SCRIPT (user-defined)\n");
				script.append(customScript);
				script.append("\n# END OF CUSTOM SCRIPT (user-defined)\n\n");
			}
			if (whitelist && logenabled) {
				script.append("# Allow DNS lookups on white-list for a better logging (ignore errors)\n");
				script.append("$IPTABLES -A droidwall -p udp --dport 53 -j RETURN\n");
			}
			script.append("# Main rules (per interface)\n");
			for (final String itf : ITFS_3G) {
				script.append("$IPTABLES -A droidwall -o ").append(itf).append(" -j droidwall-3g || exit\n");
			}
			for (final String itf : ITFS_WIFI) {
				script.append("$IPTABLES -A droidwall -o ").append(itf).append(" -j droidwall-wifi || exit\n");
			}
			
			script.append("# Filtering rules\n");
			final String targetRule = (whitelist ? "RETURN" : "droidwall-reject");
			final boolean any_3g = uids3g.indexOf(SPECIAL_UID_ANY) >= 0;
			final boolean any_wifi = uidsWifi.indexOf(SPECIAL_UID_ANY) >= 0;
			//final boolean any_cap = uidsCap.indexOf(SPECIAL_UID_ANY) >= 0;
			// TODO: What is this?
			final boolean any_cap = uidsCap.size() >=0 ;
			if (whitelist && !any_wifi) {
				// When "white listing" wifi, we need to ensure that the dhcp and wifi users are allowed
				int uid = android.os.Process.getUidForName("dhcp");
				if (uid != -1) {
					script.append("# dhcp user\n");
					script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner ").append(uid).append(" -j RETURN || exit\n");
				}
				uid = android.os.Process.getUidForName("wifi");
				if (uid != -1) {
					script.append("# wifi user\n");
					script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner ").append(uid).append(" -j RETURN || exit\n");
				}
				/* Allow root user as default */
				uid = android.os.Process.getUidForName("root");
				if (uid != -1) {
					script.append("# root user\n");
					script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner ").append(uid).append(" -j RETURN || exit\n");
				}
			}
			if (any_3g) {
				if (blacklist) {
					/* block any application on this interface */
					script.append("$IPTABLES -A droidwall-3g -j ").append(targetRule).append(" || exit\n");
				}
			} else {
				/* Allow root user as default */
				int root = android.os.Process.getUidForName("root");
				if (root != -1) {
					script.append("# root user\n");
					script.append("$IPTABLES -A droidwall-3g -m owner --uid-owner ").append(root).append(" -j RETURN || exit\n");
				}
				/* release/block individual applications on this interface */
				for (final Integer uid : uids3g) {
					if (uid >= 0) script.append("$IPTABLES -A droidwall-3g -m owner --uid-owner ").append(uid).append(" -j ").append(targetRule).append(" || exit\n");
				}
			}
			if (any_wifi) {
				if (blacklist) {
					/* block any application on this interface */
					script.append("$IPTABLES -A droidwall-wifi -j ").append(targetRule).append(" || exit\n");
				}
			} else {
				/* release/block individual applications on this interface */
				for (final Integer uid : uidsWifi) {
					if (uid >= 0) script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner ").append(uid).append(" -j ").append(targetRule).append(" || exit\n");
				}
			}
			if (whitelist) {
				/* Allow SPECIAL_UID_KERNEL as default */
				if (!any_3g) {
						script.append("# hack to allow kernel packets on white-list\n");
						script.append("$IPTABLES -A droidwall-3g -m owner --uid-owner 0:999999999 -j droidwall-reject || exit\n");
				}
				if (!any_wifi) {
						script.append("# hack to allow kernel packets on white-list\n");
						script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner 0:999999999 -j droidwall-reject || exit\n");
				}
			} else {
				if (uids3g.indexOf(SPECIAL_UID_KERNEL) >= 0) {
					script.append("# hack to BLOCK kernel packets on black-list\n");
					script.append("$IPTABLES -A droidwall-3g -m owner --uid-owner 0:999999999 -j RETURN || exit\n");
					script.append("$IPTABLES -A droidwall-3g -j droidwall-reject || exit\n");
				}
				if (uidsWifi.indexOf(SPECIAL_UID_KERNEL) >= 0) {
					script.append("# hack to BLOCK kernel packets on black-list\n");
					script.append("$IPTABLES -A droidwall-wifi -m owner --uid-owner 0:999999999 -j RETURN || exit\n");
					script.append("$IPTABLES -A droidwall-wifi -j droidwall-reject || exit\n");
				}
			}
			if (any_cap){
				for (final Integer uid : uidsCap) {
					//if (uid >= 10000) script.append("$IPTABLES -t nat -A capture -m owner --uid-owner ").append(uid).append(" -p tcp --dport 443 -j DNAT --to 127.0.0.1:8443 || exit\n");
					if (uid >= 10000){
						for (final String port : sslPort)
							script.append("$IPTABLES -t nat -A capture -m owner --uid-owner ").append(uid).append(" -p tcp --dport ").append(port).append(" -j DNAT --to 127.0.0.1:8443 || exit\n");
					}
				}
			}
	    	final StringBuilder res = new StringBuilder();
			code = runScriptAsRoot(ctx, script.toString(), res);
			if (showErrors && code != 0) {
				String msg = res.toString();
				Log.e("DroidWall", msg);
				// Remove unnecessary help message from output
				if (msg.indexOf("\nTry `iptables -h' or 'iptables --help' for more information.") != -1) {
					msg = msg.replace("\nTry `iptables -h' or 'iptables --help' for more information.", "");
				}
				alert(ctx, "Error applying iptables rules. Exit code: " + code + "\n\n" + msg.trim());
			} else {
				return true;
			}
		} catch (Exception e) {
			if (showErrors) alert(ctx, "error refreshing iptables: " + e);
		}
		return false;
    }
    /**
     * Purge and re-add all saved rules (not in-memory ones).
     * This is much faster than just calling "applyIptablesRules", since it don't need to read installed applications.
     * @param ctx application context (mandatory)
     * @param showErrors indicates if errors should be alerted
     */
	public static boolean applySavedIptablesRules(Context ctx, boolean showErrors) {
		return applySavedIptablesRules(ctx, showErrors, DEF_SSL_PORT);
	}

	public static boolean applySavedIptablesRules(Context ctx, boolean showErrors, String sslPortsStr) {
		if (ctx == null) {
			return false;
		}
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		//final String savedUids_wifi = prefs.getString(PREF_WIFI_UIDS, "");
		//final String savedUids_3g = prefs.getString(PREF_3G_UIDS, "");
		final String savedUids_cap = prefs.getString(PREF_CAP_UIDS, "");
		/*final List<Integer> uids_wifi = new LinkedList<Integer>();
		if (savedUids_wifi.length() > 0) {
			// Check which applications are allowed on wifi
			final StringTokenizer tok = new StringTokenizer(savedUids_wifi, "|");
			while (tok.hasMoreTokens()) {
				final String uid = tok.nextToken();
				if (!uid.equals("")) {
					try {
						uids_wifi.add(Integer.parseInt(uid));
					} catch (Exception ex) {
					}
				}
			}
		}
		final List<Integer> uids_3g = new LinkedList<Integer>();
		if (savedUids_3g.length() > 0) {
			// Check which applications are allowed on 2G/3G
			final StringTokenizer tok = new StringTokenizer(savedUids_3g, "|");
			while (tok.hasMoreTokens()) {
				final String uid = tok.nextToken();
				if (!uid.equals("")) {
					try {
						uids_3g.add(Integer.parseInt(uid));
					} catch (Exception ex) {
					}
				}
			}
		}*/
		final List<Integer> uids_cap = new LinkedList<Integer>();
		if (savedUids_cap.length() > 0) {
			final StringTokenizer tok = new StringTokenizer(savedUids_cap, "|");
			while (tok.hasMoreTokens()) {
				final String uid = tok.nextToken();
				if (!uid.equals("")) {
					try {
						uids_cap.add(Integer.parseInt(uid));
					} catch (Exception ex) {
					}
				}
			}
		}
		final List<String> sslPorts = new LinkedList<String>();
		if (sslPortsStr.length() > 0) {
			final StringTokenizer tok = new StringTokenizer(sslPortsStr, "|");
			while (tok.hasMoreTokens()) {
				final String port = tok.nextToken();
				if (!port.equals("")) {
					try {
						sslPorts.add(port);
					} catch (Exception ex) {
					}
				}
			}
		} else {
			sslPorts.add(DEF_SSL_PORT);
		}
		return applyIptablesRulesImpl(ctx, uids_cap, uids_cap, uids_cap, sslPorts, showErrors);
	}
	
    /**
     * Purge and re-add all rules.
     * @param ctx application context (mandatory)
     * @param showErrors indicates if errors should be alerted
     */
	public static boolean applyIptablesRules(Context ctx, boolean showErrors) {
		if (ctx == null) {
			return false;
		}
		saveRules(ctx);
		return applySavedIptablesRules(ctx, showErrors);
    }
	
	/**
	 * Save current rules using the preferences storage.
	 * @param ctx application context (mandatory)
	 */
	public static void saveRules(Context ctx) {
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		final DroidApp[] apps = getApps(ctx);
		// Builds a pipe-separated list of names
		final StringBuilder newuids_cap = new StringBuilder();
		for (int i=0; i<apps.length; i++) {
			if (apps[i].selected_cap) {
				if (newuids_cap.length() != 0) newuids_cap.append('|');
				newuids_cap.append(apps[i].uid);
			}
		}
		// save the new list of UIDs
		final Editor edit = prefs.edit();
		edit.putString(PREF_CAP_UIDS, newuids_cap.toString());
		edit.commit();
    }
    
    /**
     * Purge all iptables rules.
     * @param ctx mandatory context
     * @param showErrors indicates if errors should be alerted
     * @return true if the rules were purged
     */
	public static boolean purgeIptables(Context ctx, boolean showErrors) {
    	final StringBuilder res = new StringBuilder();
		try {
			assertBinaries(ctx, showErrors);
			// Custom "shutdown" script
			final String customScript = ctx.getSharedPreferences(Api.PREFS_NAME, 0).getString(Api.PREF_CUSTOMSCRIPT2, "");
	    	final StringBuilder script = new StringBuilder();
	    	script.append(scriptHeader(ctx));
	    	script.append("" +
					"$IPTABLES -F droidwall\n" +
					"$IPTABLES -F droidwall-reject\n" +
					"$IPTABLES -F droidwall-3g\n" +
					"$IPTABLES -F droidwall-wifi\n" +
					"$IPTABLES -t nat -F capture\n" +
	    			"");
	    	if (customScript.length() > 0) {
				script.append("\n# BEGIN OF CUSTOM SCRIPT (user-defined)\n");
				script.append(customScript);
				script.append("\n# END OF CUSTOM SCRIPT (user-defined)\n\n");
	    	}
			int code = runScriptAsRoot(ctx, script.toString(), res);
			if (code == -1) {
				if (showErrors) alert(ctx, "Error purging iptables. exit code: " + code + "\n" + res);
				return false;
			}
			return true;
		} catch (Exception e) {
			if (showErrors) alert(ctx, "Error purging iptables: " + e);
			return false;
		}
    }
	
	/**
	 * Display iptables rules output
	 * @param ctx application context
	 */
	public static void showIptablesRules(Context ctx) {
		try {
    		final StringBuilder res = new StringBuilder();
			runScriptAsRoot(ctx, scriptHeader(ctx) +
								 "$ECHO $IPTABLES\n" +
								 "$IPTABLES -L -v -n\n", res);
			alert(ctx, res);
		} catch (Exception e) {
			alert(ctx, "error: " + e);
		}
	}

	/**
	 * Display logs
	 * @param ctx application context
     * @return true if the clogs were cleared
	 */
	public static boolean clearLog(Context ctx) {
		try {
			final StringBuilder res = new StringBuilder();
			int code = runScriptAsRoot(ctx, "dmesg -c >/dev/null || exit\n", res);
			if (code != 0) {
				alert(ctx, res);
				return false;
			}
			return true;
		} catch (Exception e) {
			alert(ctx, "error: " + e);
		}
		return false;
	}
	/**
	 * Display logs
	 * @param ctx application context
	 */
	public static void showLog(Context ctx) {
		try {
    		StringBuilder res = new StringBuilder();
			int code = runScriptAsRoot(ctx, scriptHeader(ctx) +
					"dmesg | $GREP DROIDWALL\n", res);
			if (code != 0) {
				if (res.length() == 0) {
					res.append("Log is empty");
				}
				alert(ctx, res);
				return;
			}
			final BufferedReader r = new BufferedReader(new StringReader(res.toString()));
			final Integer unknownUID = -99;
			res = new StringBuilder();
			String line;
			int start, end;
			Integer appid;
			final HashMap<Integer, LogInfo> map = new HashMap<Integer, LogInfo>();
			LogInfo loginfo = null;
			while ((line = r.readLine()) != null) {
				if (line.indexOf("[DROIDWALL]") == -1) continue;
				appid = unknownUID;
				if (((start=line.indexOf("UID=")) != -1) && ((end=line.indexOf(" ", start)) != -1)) {
					appid = Integer.parseInt(line.substring(start+4, end));
				}
				loginfo = map.get(appid);
				if (loginfo == null) {
					loginfo = new LogInfo();
					map.put(appid, loginfo);
				}
				loginfo.totalBlocked += 1;
				if (((start=line.indexOf("DST=")) != -1) && ((end=line.indexOf(" ", start)) != -1)) {
					String dst = line.substring(start+4, end);
					if (loginfo.dstBlocked.containsKey(dst)) {
						loginfo.dstBlocked.put(dst, loginfo.dstBlocked.get(dst) + 1);
					} else {
						loginfo.dstBlocked.put(dst, 1);
					}
				}
			}
			final DroidApp[] apps = getApps(ctx);
			for (Integer id : map.keySet()) {
				res.append("App ID ");
				if (id != unknownUID) {
					res.append(id);
					for (DroidApp app : apps) {
						if (app.uid == id) {
							res.append(" (").append(app.names[0]);
							if (app.names.length > 1) {
								res.append(", ...)");
							} else {
								res.append(")");
							}
							break;
						}
					}
				} else {
					res.append("(kernel)");
				}
				loginfo = map.get(id);
				res.append(" - Blocked ").append(loginfo.totalBlocked).append(" packets");
				if (loginfo.dstBlocked.size() > 0) {
					res.append(" (");
					boolean first = true;
					for (String dst : loginfo.dstBlocked.keySet()) {
						if (!first) {
							res.append(", ");
						}
						res.append(loginfo.dstBlocked.get(dst)).append(" packets for ").append(dst);
						first = false;
					}
					res.append(")");
				}
				res.append("\n\n");
			}
			if (res.length() == 0) {
				res.append("Log is empty");
			}
			alert(ctx, res);
		} catch (Exception e) {
			alert(ctx, "error: " + e);
		}
	}
	/**
	 * Execute tcpump and sslsplit to start capture.
	 * @param ctx application context
	 */
	public static void execCapture(Context ctx, String capDir, String netif){
		startRAWCapture(ctx, capDir + "/pcap", netif);
		startSSLCapture(ctx,capDir + "/ssl");
	}
	/**
	 * Kill tcpump and sslsplit to stop capture.
	 * @param ctx application context
	 */
	public static void killCapture(Context ctx){
		StringBuilder res = new StringBuilder();
		String script = scriptHeader(ctx);
		script += "$BUSYBOX killall " + BIN_SSLSPLIT + "\n";
		script += "$BUSYBOX killall " + BIN_TCPDUMP + "\n";
		runScriptAsRoot(ctx, script, res, 1000);
		Editor edit = ctx.getSharedPreferences(PREFS_NAME,0).edit();
		edit.putBoolean(PREF_SSLCAP,false);
		edit.putBoolean(PREF_RAWCAP,false);
		edit.commit();
	}
	/**
	 * @param ctx application context
	 * @return status of sslsplit
	 */
	public static boolean startSSLCapture(Context ctx, String capDir){
		final StringBuilder script = new StringBuilder();
		StringBuilder res = new StringBuilder();
		String crtfile = ctx.getDir("bin",0) + "/ca_crt";
		String keyfile = ctx.getDir("bin",0) + "/ca_key";
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME,0);
		Editor edit = prefs.edit();
		try{
			script.append(scriptHeader(ctx));
			script.append("$BUSYBOX mkdir -p " + capDir + "\n");
			script.append("$SSLSPLIT -c " + crtfile + " -k " + keyfile + " -S "+ capDir + " -d ssl 127.0.0.1 8443");
			runScriptAsRoot(ctx,script.toString(),res,1000);
			edit.putBoolean(PREF_SSLCAP,true);
			edit.commit();
			return true;
		}catch (Exception e) {
			alert(ctx, "error starting sslsplit: " + e);
		}
		return false;
	}

	/**
	 * @param ctx application context
	 * @param capDir directory to save capture file
	 * @param netif interface to be captured
	 * @return status of tcpdump
	 */
	public static boolean startRAWCapture(Context ctx, String capDir, String netif){
		final StringBuilder script = new StringBuilder();
		StringBuilder res = new StringBuilder();
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME,0);
		Editor edit = prefs.edit();
		try{
			script.append(scriptHeader(ctx));
			script.append("$BUSYBOX mkdir -p " + capDir + "\n");
			script.append("$TCPDUMP -i " + netif + " -w " + capDir + "/main.pcap ip &");
			runScriptAsRoot(ctx,script.toString(),res,1000);
			edit.putBoolean(PREF_RAWCAP,true);
			edit.commit();
			return true;
		}catch (Exception e) {
			alert(ctx, "error starting tcpdump: " + e);
		}
		return false;
	}

	/**
	 * Clear status of tcpdump and sslsplit in shared preferences.
	 * @param ctx application context
	 */
	public static void clearCaptureStatusOnBoot(Context ctx){
		boolean changed = false;
		boolean sslEnabled;
		boolean rawEnabled;
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME,0);
		Editor edit = prefs.edit();
		/*
		sslEnabled = prefs.getBoolean(PREF_SSLCAP, true);
		rawEnabled = prefs.getBoolean(PREF_RAWCAP, true);
		if (sslEnabled) {
			edit.putBoolean(PREF_SSLCAP,false);
		}
		if (rawEnabled) {
			edit.putBoolean(PREF_RAWCAP,false);
		}
		if (sslEnabled||rawEnabled) edit.commit();
		*/
		edit.putBoolean(PREF_SSLCAP,false);
		edit.putBoolean(PREF_RAWCAP,false);
		edit.putBoolean(PREF_AUTOCAP,false);
		edit.commit();
		setAutoCapStatus(ctx, false);
	}

	/**
	 * Find PIDs of progress whose name includes given string
	 * @param ctx application context
	 * @param name (a part of) name of progress
	 * @return a list of PID of given name
	 */
	public static ArrayList<Integer> getPidByName(Context ctx, String name){
		ArrayList<Integer> pidList=new ArrayList<Integer>();
		StringBuilder script = new StringBuilder();
		StringBuilder res = new StringBuilder();
		script.append(scriptHeader(ctx));
		script.append("$BUSYBOX ps -o pid,comm | $BUSYBOX grep ");
		script.append(name);
		script.append(" | $BUSYBOX awk \'{print $1}\'\n");
		runScriptAsRoot(ctx,script.toString(),res,1000);
		String[] pidStrArr = res.toString().split("\n");
		for (String pidStr:pidStrArr) {
			try {
				pidList.add(Integer.parseInt(pidStr));
			}catch (Exception e){}

		}
		return pidList;
	}

    /**
     * @param ctx application context (mandatory)
     * @return a list of applications
     */
	public static DroidApp[] getApps(Context ctx) {
		if (applications != null) {
			// return cached instance
			return applications;
		}
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		// allowed application names separated by pipe '|' (persisted)
		final String savedUids_cap = prefs.getString(PREF_CAP_UIDS, "");
		int selected_cap[] = new int[0];
		if (savedUids_cap.length() > 0) {
			// Check which applications are allowed
			final StringTokenizer tok = new StringTokenizer(savedUids_cap, "|");
			selected_cap = new int[tok.countTokens()];
			for (int i=0; i<selected_cap.length; i++) {
				final String uid = tok.nextToken();
				if (!uid.equals("")) {
					try {
						selected_cap[i] = Integer.parseInt(uid);
					} catch (Exception ex) {
						selected_cap[i] = -1;
					}
				}
			}
			// Sort the array to allow using "Arrays.binarySearch" later
			Arrays.sort(selected_cap);
		}
		try {
			final PackageManager pkgmanager = ctx.getPackageManager();
			final List<ApplicationInfo> installed = pkgmanager.getInstalledApplications(0);
			final HashMap<Integer, DroidApp> map = new HashMap<Integer, DroidApp>();
			final Editor edit = prefs.edit();
			boolean changed = false;
			String name = null;
			String cachekey = null;
			DroidApp app = null;
			for (final ApplicationInfo apinfo : installed) {
				boolean firstseem = false;
				app = map.get(apinfo.uid);
				// filter applications which are not allowed to access the Internet
				if (app == null && PackageManager.PERMISSION_GRANTED != pkgmanager.checkPermission(Manifest.permission.INTERNET, apinfo.packageName)) {
					continue;
				}
				// try to get the application label from our cache - getApplicationLabel() is horribly slow!!!!
				cachekey = "cache.label."+apinfo.packageName;
				name = prefs.getString(cachekey, "");
				if (name.length() == 0) {
					// get label and put on cache
					name = pkgmanager.getApplicationLabel(apinfo).toString();
					edit.putString(cachekey, name);
					changed = true;
					firstseem = true;
				}
				if (app == null) {
					app = new DroidApp();
					app.uid = apinfo.uid;
					app.names = new String[] { name };
					app.appinfo = apinfo;
					map.put(apinfo.uid, app);
				} else {
					final String newnames[] = new String[app.names.length + 1];
					System.arraycopy(app.names, 0, newnames, 0, app.names.length);
					newnames[app.names.length] = name;
					app.names = newnames;
				}
				app.firstseem = firstseem;
				if (!app.selected_cap && Arrays.binarySearch(selected_cap, app.uid) >= 0) {
					app.selected_wifi = true;
					app.selected_3g = true;
					app.selected_cap = true;
				}
			}
			if (changed) {
				edit.commit();
			}
			/* add special applications to the list */
			/*final DroidApp special[] = {
				new DroidApp(SPECIAL_UID_ANY,"(Any application) - Same as selecting all applications", false, false, false),
				new DroidApp(SPECIAL_UID_KERNEL,"(Kernel) - Linux kernel", false, false, false),
				new DroidApp(android.os.Process.getUidForName("root"), "(root) - Applications running as root", false, false, false),
				new DroidApp(android.os.Process.getUidForName("media"), "Media server", false, false, false),
				new DroidApp(android.os.Process.getUidForName("vpn"), "VPN networking", false, false, false),
				new DroidApp(android.os.Process.getUidForName("shell"), "Linux shell", false, false, false),
				new DroidApp(android.os.Process.getUidForName("gps"), "GPS", false, false, false),
			};
			for (int i=0; i<special.length; i++) {
				app = special[i];
				if (app.uid != -1 && !map.containsKey(app.uid)) {
					// check if this application is allowed
					if (Arrays.binarySearch(selected_cap, app.uid) >= 0) {
						app.selected_wifi = true;
						app.selected_3g = true;
						app.selected_cap = true;
					}
					map.put(app.uid, app);
				}
			}*/
			/* convert the map into an array */
			applications = map.values().toArray(new DroidApp[map.size()]);;
			return applications;
		} catch (Exception e) {
			alert(ctx, "error: " + e);
		}
		return null;
	}
	/**
	 * Check if we have root access
	 * @param ctx mandatory context
     * @param showErrors indicates if errors should be alerted
	 * @return boolean true if we have root
	 */
	public static boolean hasRootAccess(final Context ctx, boolean showErrors) {
		if (hasroot) return true;
		final StringBuilder res = new StringBuilder();
		try {
			// Run an empty script just to check root access
			if (runScriptAsRoot(ctx, "exit 0", res) == 0) {
				hasroot = true;
				return true;
			}
		} catch (Exception e) {
		}
		if (showErrors) {
			alert(ctx, "Could not acquire root access.\n" +
				"You need a rooted phone to run DroidWall.\n\n" +
				"If this phone is already rooted, please make sure DroidWall has enough permissions to execute the \"su\" command.\n" +
				"Error message: " + res.toString());
		}
		return false;
	}
    /**
     * Runs a script, wither as root or as a regular user (multiple commands separated by "\n").
	 * @param ctx mandatory context
     * @param script the script to be executed
     * @param res the script output response (stdout + stderr)
     * @param timeout timeout in milliseconds (-1 for none)
     * @return the script exit code
     */
	public static int runScript(Context ctx, String script, StringBuilder res, long timeout, boolean asroot) {
		final File file = new File(ctx.getDir("bin",0), SCRIPT_FILE);
		final ScriptRunner runner = new ScriptRunner(file, script, res, asroot);
		runner.start();
		try {
			if (timeout > 0) {
				runner.join(timeout);
			} else {
				runner.join();
			}
			if (runner.isAlive()) {
				// Timed-out
				runner.interrupt();
				runner.join(150);
				runner.destroy();
				runner.join(50);
			}
		} catch (InterruptedException ex) {}
		return runner.exitcode;
	}
    /**
     * Runs a script as root (multiple commands separated by "\n").
	 * @param ctx mandatory context
     * @param script the script to be executed
     * @param res the script output response (stdout + stderr)
     * @param timeout timeout in milliseconds (-1 for none)
     * @return the script exit code
     */
	public static int runScriptAsRoot(Context ctx, String script, StringBuilder res, long timeout) {
		return runScript(ctx, script, res, timeout, true);
    }
    /**
     * Runs a script as root (multiple commands separated by "\n") with a default timeout of 20 seconds.
	 * @param ctx mandatory context
     * @param script the script to be executed
     * @param res the script output response (stdout + stderr)
     * @return the script exit code
     * @throws IOException on any error executing the script, or writing it to disk
     */
	public static int runScriptAsRoot(Context ctx, String script, StringBuilder res) throws IOException {
		return runScriptAsRoot(ctx, script, res, 40000);
	}
    /**
     * Runs a script as a regular user (multiple commands separated by "\n") with a default timeout of 20 seconds.
	 * @param ctx mandatory context
     * @param script the script to be executed
     * @param res the script output response (stdout + stderr)
     * @return the script exit code
     * @throws IOException on any error executing the script, or writing it to disk
     */
	public static int runScript(Context ctx, String script, StringBuilder res) throws IOException {
		return runScript(ctx, script, res, 40000, false);
	}
	/**
	 * Asserts that the binary files are installed in the cache directory.
	 * @param ctx context
     * @param showErrors indicates if errors should be alerted
	 * @return false if the binary files could not be installed
	 */
	public static boolean assertBinaries(Context ctx, boolean showErrors) {
		boolean changed = false;
		try {
			// Check iptables_armv5
			File file = new File(ctx.getDir("bin",0), "iptables_armv5");
			if (!file.exists() || file.length()!=198652) {
				copyRawFile(ctx, R.raw.iptables_armv5, file, "755");
				changed = true;
			}
			// Check busybox
			file = new File(ctx.getDir("bin",0), "busybox_armv6l");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.busybox_armv6l, file, "755");
				changed = true;
			}
			file = new File(ctx.getDir("bin",0), "busybox_x86");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.busybox_x86, file, "755");
				changed = true;
			}
			// Check sslsplit
			file = new File(ctx.getDir("bin",0), "sslsplit_armv7hf");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.sslsplit_armv7hf, file, "755");
				changed = true;
			}
			file = new File(ctx.getDir("bin",0), "sslsplit_x86");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.sslsplit_x86, file, "755");
				changed = true;
			}
			// Check tcpdump
			file = new File(ctx.getDir("bin",0), "tcpdump_armv7hf");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.tcpdump_armv7hf, file, "755");
				changed = true;
			}
			file = new File(ctx.getDir("bin",0), "tcpdump_x86");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.tcpdump_x86, file, "755");
				changed = true;
			}
			// Check certs
			file = new File(ctx.getDir("bin",0), "ca_crt");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.ca_crt, file, "644");
				changed = true;
			}
			file = new File(ctx.getDir("bin",0), "ca_key");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.ca_key, file, "644");
				changed = true;
			}
			file = new File(ctx.getDir("bin",0), "uaplugin.jar");
			if (!file.exists()) {
				copyRawFile(ctx, R.raw.uaplugin, file, "644");
				changed = true;
			}
			if (changed) {
				Toast.makeText(ctx, R.string.toast_bin_installed, Toast.LENGTH_LONG).show();
			}
		} catch (Exception e) {
			if (showErrors) alert(ctx, "Error installing binary files: " + e);
			return false;
		}
		return true;
	}
	/**
	 * Check if the firewall is enabled
	 * @param ctx mandatory context
	 * @return boolean
	 */
	public static boolean isEnabled(Context ctx) {
		if (ctx == null) return false;
		return ctx.getSharedPreferences(PREFS_NAME, 0).getBoolean(PREF_ENABLED, false);
	}
	
	/**
	 * Defines if the firewall is enabled and broadcasts the new status
	 * @param ctx mandatory context
	 * @param enabled enabled flag
	 */
	public static void setEnabled(Context ctx, boolean enabled) {
		if (ctx == null) return;
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		if (prefs.getBoolean(PREF_ENABLED, false) == enabled) {
			return;
		}
		final Editor edit = prefs.edit();
		edit.putBoolean(PREF_ENABLED, enabled);
		if (!edit.commit()) {
			alert(ctx, "Error writing to preferences");
			return;
		}
		/* notify */
		final Intent message = new Intent(Api.STATUS_CHANGED_MSG);
        message.putExtra(Api.STATUS_EXTRA, enabled);
        ctx.sendBroadcast(message);
	}
	/**
	 * Called when an application in removed (un-installed) from the system.
	 * This will look for that application in the selected list and update the persisted values if necessary
	 * @param ctx mandatory app context
	 * @param uid UID of the application that has been removed
	 */
	public static void applicationRemoved(Context ctx, int uid) {
		final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		final Editor editor = prefs.edit();
		// allowed application names separated by pipe '|' (persisted)
		final String savedUids_cap = prefs.getString(PREF_CAP_UIDS, "");
		final String uid_str = uid + "";
		boolean changed = false;
		// look for the removed application in the "cap" list
		if (savedUids_cap.length() > 0) {
			final StringBuilder newuids = new StringBuilder();
			final StringTokenizer tok = new StringTokenizer(savedUids_cap, "|");
			while (tok.hasMoreTokens()) {
				final String token = tok.nextToken();
				if (uid_str.equals(token)) {
					Log.d("DroidWall", "Removing UID " + token + " from the cap list (package removed)!");
					changed = true;
				} else {
					if (newuids.length() > 0) newuids.append('|');
					newuids.append(token);
				}
			}
			if (changed) {
				editor.putString(PREF_CAP_UIDS, newuids.toString());
			}
		}
		// if anything has changed, save the new prefs...
		if (changed) {
			editor.commit();
			if (isEnabled(ctx)) {
				// .. and also re-apply the rules if the firewall is enabled
				applySavedIptablesRules(ctx, false);
			}
		}
	}

	//===== ↓ Automatic test and capture ↓ =====//
	public static boolean getAutoCapStatus(Context ctx){
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME,0);
		return prefs.getBoolean(PREF_AUTOCAP,false);
	}

	public static void setAutoCapStatus(Context ctx, boolean status){
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME,0);
		Editor edit = prefs.edit();
		edit.putBoolean(PREF_AUTOCAP,status);
		edit.commit();
		//if (!status){
			unsetAllCap(ctx);
			//killMonkeys(ctx);
		//} else
	}

	public static HashMap<String, Integer> getAppDict(Context ctx, String name){
		final PackageManager pkgmanager = ctx.getPackageManager();
		final List<ApplicationInfo> installed = pkgmanager.getInstalledApplications(0);
		final HashMap<String, Integer> map = new HashMap<String, Integer>();
		for (final ApplicationInfo apinfo : installed){
			map.put(apinfo.packageName, apinfo.uid);
		}
		return map;
	}

	public static int getUidByName(Context ctx, String name){
		HashMap<String, Integer> map = getAppDict(ctx, name);
		return map.get(name);
	}

	public static void setCapForSpecApp(Context ctx, String pkgName, String ports){
		Date date = new Date();
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd,HH-mm-ss");
		String timeStr = df.format(date);
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		String autocap_current = prefs.getString(PREF_AUTOCAP_CURRENT, "");
		Integer uid;
		if (autocap_current.isEmpty()){
			unsetAllCap(ctx);
		}
		try{
			uid = getUidByName(ctx, pkgName);final Editor edit = prefs.edit();
			edit.putString(PREF_CAP_UIDS, uid.toString());
			edit.putString(PREF_AUTOCAP_CURRENT, uid.toString());
			edit.commit();
			Api.setEnabled(ctx, true);
			Api.applySavedIptablesRules(ctx,true, ports);
			Api.execCapture(ctx, Api.DIR_CAPTURE + "/" + pkgName + "," + timeStr, "wlan0");
			applications = null;
		} catch ( NullPointerException ex) {
			Log.e(TAG, "setCapForSpecApp: No specified app " + pkgName, ex);
			Toast.makeText(ctx, "setCapForSpecApp: No specified app " + pkgName, Toast.LENGTH_LONG).show();
			return;
		}
	}

	public static void unsetAllCap(Context ctx){
		SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
		final Editor edit = prefs.edit();
		edit.putString(PREF_CAP_UIDS, "");
		edit.putString(PREF_AUTOCAP_CURRENT, "");
		edit.commit();
		Api.setEnabled(ctx, false);
		purgeIptables(ctx, true);
		Api.killCapture(ctx);
		applications = null;
	}
	//===== ↑ Automatic test and capture ↑ =====//

    /**
     * Small structure to hold an application info
     */
	public static final class DroidApp {
		/** linux user id */
    	int uid;
    	/** application names belonging to this user id */
    	String names[];
    	/** indicates if this application is selected for wifi */
    	boolean selected_wifi;
    	/** indicates if this application is selected for 3g */
    	boolean selected_3g;
		/** indicates if this application is selected for capture */
		boolean selected_cap;
    	/** toString cache */
    	String tostr;
    	/** application info */
    	ApplicationInfo appinfo;
    	/** cached application icon */
    	Drawable cached_icon;
    	/** indicates if the icon has been loaded already */
    	boolean icon_loaded;
    	/** first time seem? */
    	boolean firstseem;
    	
    	public DroidApp() {
    	}
    	public DroidApp(int uid, String name, boolean selected_wifi, boolean selected_3g, boolean selected_cap) {
    		this.uid = uid;
    		this.names = new String[] {name};
    		this.selected_wifi = selected_wifi;
    		this.selected_3g = selected_3g;
			this.selected_cap = selected_cap;
    	}
    	/**
    	 * Screen representation of this application
    	 */
    	@Override
    	public String toString() {
    		if (tostr == null) {
        		final StringBuilder s = new StringBuilder();
        		if (uid > 0) s.append(uid + ": ");
        		for (int i=0; i<names.length; i++) {
        			if (i != 0) s.append(", ");
        			s.append(names[i]);
        		}
        		s.append("\n");
        		tostr = s.toString();
    		}
    		return tostr;
    	}
    }
    /**
     * Small internal structure used to hold log information
     */
	private static final class LogInfo {
		private int totalBlocked; // Total number of packets blocked
		private HashMap<String, Integer> dstBlocked; // Number of packets blocked per destination IP address
		private LogInfo() {
			this.dstBlocked = new HashMap<String, Integer>();
		}
	}
	/**
	 * Internal thread used to execute scripts (as root or not).
	 */
	private static final class ScriptRunner extends Thread {
		private final File file;
		private final String script;
		private final StringBuilder res;
		private final boolean asroot;
		public int exitcode = -1;
		private Process exec;
		
		/**
		 * Creates a new script runner.
		 * @param file temporary script file
		 * @param script script to run
		 * @param res response output
		 * @param asroot if true, executes the script as root
		 */
		public ScriptRunner(File file, String script, StringBuilder res, boolean asroot) {
			this.file = file;
			this.script = script;
			this.res = res;
			this.asroot = asroot;
		}
		@Override
		public void run() {
			try {
				file.createNewFile();
				final String abspath = file.getAbsolutePath();
				// make sure we have execution permission on the script file
				Runtime.getRuntime().exec("chmod 777 "+abspath).waitFor();
				// Write the script to be executed
				final OutputStreamWriter out = new OutputStreamWriter(new FileOutputStream(file));
				if (new File("/system/bin/sh").exists()) {
					out.write("#!/system/bin/sh\n");
				}
				out.write(script);
				if (!script.endsWith("\n")) out.write("\n");
				out.write("exit\n");
				out.flush();
				out.close();
				if (this.asroot) {
					// Create the "su" request to run the script
					exec = Runtime.getRuntime().exec("su -c "+abspath);
				} else {
					// Create the "sh" request to run the script
					exec = Runtime.getRuntime().exec("sh "+abspath);
				}
				final InputStream stdout = exec.getInputStream();
				final InputStream stderr = exec.getErrorStream();
				final byte buf[] = new byte[8192];
				int read = 0;
				while (true) {
					final Process localexec = exec;
					if (localexec == null) break;
					try {
						// get the process exit code - will raise IllegalThreadStateException if still running
						this.exitcode = localexec.exitValue();
					} catch (IllegalThreadStateException ex) {
						// The process is still running
					}
					// Read stdout
					if (stdout.available() > 0) {
						read = stdout.read(buf);
						if (res != null) res.append(new String(buf, 0, read));
					}
					// Read stderr
					if (stderr.available() > 0) {
						read = stderr.read(buf);
						if (res != null) res.append(new String(buf, 0, read));
					}
					if (this.exitcode != -1) {
						// finished
						break;
					}
					// Sleep for the next round
					Thread.sleep(50);
				}
			} catch (InterruptedException ex) {
				if (res != null) res.append("\nOperation timed-out");
			} catch (Exception ex) {
				if (res != null) res.append("\n" + ex);
			} finally {
				destroy();
			}
		}
		/**
		 * Destroy this script runner
		 */
		public synchronized void destroy() {
			if (exec != null) exec.destroy();
			exec = null;
		}
	}
}
