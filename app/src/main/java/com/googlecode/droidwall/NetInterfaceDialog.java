/**
 * Dialog displayed to request a password.
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

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.os.Handler.Callback;
import android.os.Message;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/**
 * Dialog displayed to request a password.
 */
public class NetInterfaceDialog extends Dialog implements View.OnClickListener, View.OnKeyListener, OnCancelListener {
	private final Callback callback;
	private final EditText netif;
	/**
	 * Creates the dialog
	 * @param context context
	 * @param setting if true, indicates that we are setting a new password instead of requesting it.
	 * @param callback callback to receive the password entered (null if canceled)
	 */
	public NetInterfaceDialog(Context context, boolean setting, Callback callback) {
		super(context);
		final View view = getLayoutInflater().inflate(R.layout.netif_dialog, null);
		((TextView)view.findViewById(R.id.netif_message)).setText(setting ? R.string.enternewnetif : R.string.enternetif);
		((Button)view.findViewById(R.id.netif_ok)).setOnClickListener(this);
		((Button)view.findViewById(R.id.netif_cancel)).setOnClickListener(this);
		this.callback = callback;
		this.netif = (EditText) view.findViewById(R.id.netif_input);
		this.netif.setOnKeyListener(this);
		setTitle(setting ? R.string.netif_titleset : R.string.netif_titleget);
		setOnCancelListener(this);
		setContentView(view);
        netif.setText(context.getSharedPreferences(Api.PREFS_NAME, 0).getString(Api.PREF_NETIF, ""));
	}
	@Override
	public void onClick(View v) {
		final Message msg = new Message();
		if (v.getId() == R.id.netif_ok) {
			msg.obj = this.netif.getText().toString();
		}
		dismiss();
		this.callback.handleMessage(msg);
	}
	@Override
	public boolean onKey(View v, int keyCode, KeyEvent event) {
		if (keyCode == KeyEvent.KEYCODE_ENTER) {
			final Message msg = new Message();
			msg.obj = this.netif.getText().toString();
			this.callback.handleMessage(msg);
			dismiss();
			return true;
		}
		return false;
	}
	@Override
	public void onCancel(DialogInterface dialog) {
		this.callback.handleMessage(new Message());
	}
}
