/*
	Copyright Amit Jain 2013

	This file is part of extemporal encryption scheme implementation.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package net.extemporal.test;

import com.sun.mail.imap.IMAPFolder;

import javax.activation.DataHandler;
import javax.mail.*;
import javax.mail.event.MessageCountAdapter;
import javax.mail.event.MessageCountEvent;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.ConcurrentLinkedQueue;

import net.extemporal.Engine;

/**
 * A a more complex extension of {@link SimpleTestPlatform}. Sends messages via email. Uses JavaMail(
 * see https://javamail.java.net/nonav/docs/api/javax/mail/Message.html). <br/>
 * Note that the reference implementation of Javamail used for this class does not support connection
 * via proxies. Also, in the general case a mail specification needs 7 parameters (one email id +
 * user, password and host for bother mail transport and store) for each endpoint. <br/>
 * This has been simplified a bit if sending and receiving via gmail - only an email id and password are
 * required since other parameters can be derived from them.  Use the static functions provided for this purpose.
 * However, be aware that this has a drawback: gmail rate-limits connections to its SMTP server, and also creates
 * copies of sent replies in the inbox, in order to support its threaded view. <br/>
 */
public class EmailTestPlatform extends SimpleTestPlatform {
	final URLName mSmtpAccountURN;
	public EmailTestPlatform(String address, String imapAccountURN, String smtpAccountURN)
	{
		super(address);

		mSmtpAccountURN = new URLName(smtpAccountURN);
		final URLName imapCredentials = new URLName(imapAccountURN);

		Properties props = new Properties();
		props.put("mail.from", address);

		mSession = Session.getInstance(props);
		//mSession.setDebug(true);

		shuttingDown = false;
		mAsyncWorker = new Thread(new Runnable() {
			@Override
			public void run()
			{
				while (!shuttingDown) {
					while (!mTasks.isEmpty()) {
						mTasks.remove().run();
					}
					Thread.yield();
				}
			}
		});

		mMailChecker = new Thread(new Runnable() {
			@Override
			public void run()
			{
				try {
					monitor(imapCredentials, 2);
				}
				catch (MessagingException mex) {
					processException(mex);
				}
			}
		});

		mMailChecker.start();
		mAsyncWorker.start();
	}

	@Override
	void shutdown()
	{
		shuttingDown = true;    // this will shut down both the async worker and the mail checker
		try {
			mAsyncWorker.join();
		}
		catch (InterruptedException iex)
		{
			// ignore
		}
		mAsyncWorker = null;
		super.shutdown();
	}

	public boolean sendNewEmail(String to, String subject, String content)
	{
		int nChars = subject.length() + 1 + content.length();
		if (nChars > 1) {
			try {
				ByteBuffer msg = ByteBuffer.allocate(nChars * 2);
				msg.put(subject.getBytes("UTF-16BE"));	// so conversion back is easy
				msg.putChar('\n');
				msg.put(content.getBytes("UTF-16BE"));
				msg.flip();

				return mMessagingEngine.sendMessage(null, to, msg);
			}
			catch (UnsupportedEncodingException uee) {
				// ignore; we're returning false
			}
		}
		return false;
	}

	@Override
	public boolean openReceivedEnvelope(String from, int commType, MutablePlatformContext wrapper, boolean verifiable, Integer ourRefIfAny, Integer theirRefIfAny)
	{
		if (super.openReceivedEnvelope(from, commType, wrapper, verifiable, ourRefIfAny, theirRefIfAny) && wrapper.platformContext != null) {
			try {
				if (commType == Engine.flagMsg || commType == Engine.flagAck)
					wrapper.platformContext = ((Message)wrapper.platformContext).reply(false);
				else if (commType == Engine.flagCnf)
					wrapper.platformContext = new PendingMessage_((MimeMessage)wrapper.platformContext);	// clone
				return true;
			}
			catch (MessagingException mex) {
				System.err.println("Error replying to message: " + mex);
			}
		}
		return false;
	}

	@Override
	public boolean handleReceivedMessage(Object platformContext, String endpoint, ByteBuffer messagePlainBytes)
	{
		try {
			PendingMessage_ pm = (PendingMessage_)platformContext;
			MimeMessage msg = pm.replacement;
			if (msg != null) {
				msg.setDataHandler(null);

				byte msgBytes[] = new byte[messagePlainBytes.remaining()];
				messagePlainBytes.get(msgBytes);

				String msgChars = new String(msgBytes, "UTF-16BE");
				int newLineAt = msgChars.indexOf('\n');
				msg.setText(msgChars.substring(newLineAt + 1), "utf-8");
				if (newLineAt >= 0)
					msg.setSubject(msgChars.substring(0, newLineAt));
				/*
				CharBuffer chars = messagePlainBytes.asCharBuffer();
				while (chars.hasRemaining()) {
					char c = chars.get();
					if (c == '\n') {
						int nReadChars = chars.position();
						chars.position(nReadChars - 1);	// ignore the newline
						chars.flip();
						msg.setSubject(chars.toString());
						messagePlainBytes.position(2 * (nReadChars - 1));
						chars.position(nReadChars);
						break;
					}
				}
				byte[] mc = new byte[messagePlainBytes.remaining()];
				messagePlainBytes.get(mc);
				ByteArrayDataSource dSrc = new ByteArrayDataSource(mc, "application/octet-stream");
				msg.setDataHandler(new DataHandler(dSrc));
				*/
				pm.attach();
				return true;
			}
		}
		catch (MessagingException mex) {
			System.err.println("Can't replace the message: " + mex);
		}
		catch (UnsupportedEncodingException uex) {
			// ignore
		}
		return false;
	}

	@Override
	public byte getTypeIdentifier()
	{
		return 'E';
	}

	@Override
	public void executeAsynchronously(Runnable function)
	{
		mTasks.add(function);
	}

	@Override
	public boolean transmitBytes(Object platformContext, String endpoint, ByteBuffer messageBytes)
	{
		return transmitEmail(endpoint, messageBytes, (Message)platformContext);
	}

	@Override
	public void processException(Exception e)
	{
		System.out.println("Exception occurred! " + e.toString() + "\n");
		e.printStackTrace();
	}

	protected boolean monitor(URLName imapCredentials, int freq) throws MessagingException
	{
		final Store store = mSession.getStore(imapCredentials);
		store.connect();	// throws if can't connect

		// TODO: in case folder comes null, an example said store.getDefaultFolder().getFolder("INBOX");
		String folderName = imapCredentials.getFile();
		final Folder folder = store.getFolder(folderName != null ? folderName : "INBOX"),
					trash = store.getFolder("Trash");	// trash is only becaue because Gmail does not delete messages unless copied to trash
		if (folder == null || !folder.exists()) {
			System.err.println("Invalid folder: " + folderName);
			return false;
		}

		if (trash != null && trash.exists())
			trash.open(Folder.READ_WRITE);

		folder.open(Folder.READ_WRITE);

		folder.addMessageCountListener(new MessageCountAdapter() {	// listen for new messages
			@Override
			public void messagesAdded(MessageCountEvent ev) {
				if (ev.getType() == MessageCountEvent.ADDED && !onNewMessages(ev.getMessages(), folder, trash)) {
					folder.removeMessageCountListener(this);
				}
			}
		});

		boolean supportsIdle = false;
		try {
			if (folder instanceof IMAPFolder) {
				IMAPFolder f = (IMAPFolder)folder;
				f.idle();
				supportsIdle = true;
			}
		}
		catch (FolderClosedException fex) {
			throw fex;
		}
		catch (MessagingException mex) {
			supportsIdle = false;
		}

		while (!shuttingDown) {	// check mail every "freq" seconds
			if (supportsIdle) {
				IMAPFolder f = (IMAPFolder)folder;
				f.idle();
			}
			else {
				try {
					Thread.sleep(freq * 1000); // sleep for freq seconds
				}
				catch (InterruptedException e) {
					// ignore
				}
				folder.getMessageCount();	// force IMAP server to send us EXISTS notifications.
			}
		}
		folder.close(true);
		if (trash != null && trash.exists())
			trash.close(false);
		return true;
	}

	protected boolean onNewMessages(Message[] msgs, Folder folder, Folder trash)
	{
		System.out.println("Got " + msgs.length + " new messages");
		try {
			int d = 0;
			ByteArrayOutputStream msgContent = new ByteArrayOutputStream();
			for (Message m : msgs) {
				if (m.isSet(Flags.Flag.SEEN))	// Gmail doesn't support recent
					continue;
				if (((InternetAddress)(m.getFrom()[0])).getAddress().equals(mEndpoint)) {
					System.err.println("Gmail has created a ghost message!");	// gmail creates these, most likely to support threaded conversations in inbox
					m.setFlag(Flags.Flag.DELETED, true);
					++d;
					continue;
				}
				String from = ((InternetAddress)(m.getFrom()[0])).getAddress();
				System.out.println(mEndpoint + ": message #" + m.getMessageNumber() + " from " + from);
				msgContent.reset();
				m.getDataHandler().writeTo(msgContent);
				switch(mMessagingEngine.processReceivedEnvelope(m, from, ByteBuffer.wrap(msgContent.toByteArray()))) {
					case Processed:
						m.setFlag(Flags.Flag.ANSWERED, true);
						if (trash != null && trash.exists())
							folder.copyMessages(new Message[] {m}, trash);
						m.setFlag(Flags.Flag.DELETED, true);	// if need to delete
						++d;
						break;
					case Failed:
						System.err.println("Failed processing of the message!");
					case Ignored:
				}
			}
			if (d > 0)
				folder.expunge();
			return true;
		}
		catch (MessagingException mex) {
			mex.printStackTrace();
			return false;
		}
		catch (IOException iox) {
			iox.printStackTrace();
			return false;
		}
	}

	protected boolean transmitEmail(String to, ByteBuffer msgContent, Message emailSkeleton)
	{
		try {
			if (emailSkeleton == null) {
				emailSkeleton = new MimeMessage(mSession);
				emailSkeleton.setFrom(new InternetAddress(mEndpoint));
				emailSkeleton.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
			}

			byte[] mc = new byte[msgContent.remaining()];
			msgContent.get(mc);
			ByteArrayDataSource dSrc = new ByteArrayDataSource(mc, "application/octet-stream");
			emailSkeleton.setDataHandler(new DataHandler(dSrc));

			final Transport channel = mSession.getTransport(mSmtpAccountURN);
			channel.connect();	// throws if can't connect
			channel.sendMessage(emailSkeleton, emailSkeleton.getRecipients(Message.RecipientType.TO));
			channel.close();
		}
		catch (MessagingException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	protected final Session mSession;
	protected ConcurrentLinkedQueue<Runnable> mTasks = new ConcurrentLinkedQueue<Runnable>();
	Thread mAsyncWorker, mMailChecker;
	volatile boolean shuttingDown;

	public static EmailTestPlatform createFromGmailCredentials(String emailId, String password)
	{
		// verify that the address is a valid email
		String[] parts = (emailId).split("@");
		if (parts.length == 1 && parts[0].trim().length() > 0) {
			emailId += "@gmail.com";
		}
		if (parts.length != 2 ||
				parts[0] == null || parts[0].length() < 1 ||
				parts[1] == null || parts[1].length() < 3 || parts[1].indexOf('.') < 0) {
			throw new IllegalArgumentException("Invalid email id supplied: " + emailId);
		}

		final URLName storeURN = new URLName("imaps", "imap.gmail.com", -1, "INBOX", emailId, password),
						transportURN = new URLName("smtps", "smtp.gmail.com", -1, null, emailId, password);

		return new EmailTestPlatform(emailId, storeURN.toString(), transportURN.toString());
	}

	public static String[] getGMailCredentials(String emailId, String password)
	{
		String[] parts = (emailId).split("@");
		if (parts.length == 1 && parts[0].trim().length() > 0) {
			emailId += "@gmail.com";
		}
		if (parts.length != 2 ||
				parts[0] == null || parts[0].length() < 1 ||
				parts[1] == null || parts[1].length() < 3 || parts[1].indexOf('.') < 0) {
			throw new IllegalArgumentException("Invalid email id supplied: " + emailId);
		}

		final URLName storeURN = new URLName("imaps", "imap.gmail.com", -1, "INBOX", emailId, password),
				transportURN = new URLName("smtps", "smtp.gmail.com", -1, null, emailId, password);

		return new String[] { emailId, storeURN.toString(), transportURN.toString() };
	}

	static protected class PendingMessage_ {
		final MimeMessage replacement;
		final Folder mFolder;

		PendingMessage_(MimeMessage m) throws MessagingException
		{
			mFolder = m.getFolder();
			replacement = new MimeMessage(m.getSession());
			replacement.setSentDate(m.getSentDate());
			replacement.setFrom(m.getFrom()[0]);
			replacement.setSender(m.getSender());
			replacement.setReplyTo(m.getReplyTo());
			replacement.setRecipients(Message.RecipientType.TO, m.getRecipients(Message.RecipientType.TO));
			replacement.setRecipients(Message.RecipientType.CC, m.getRecipients(Message.RecipientType.CC));
			replacement.setRecipients(Message.RecipientType.BCC, m.getRecipients(Message.RecipientType.BCC));
			replacement.setContentID(m.getContentID());
			for (Enumeration headers = m.getMatchingHeaders(relevantHeaders); headers.hasMoreElements(); ) {
				Header h = (Header)headers.nextElement();
				replacement.addHeader(h.getName(), h.getValue());
			}
			/*
			// doesn't work. Message text gets encrypted by the key held in original message object, I think.
			replacement = new MimeMessage(m);
			replacement.removeHeader("MIME-Version");	// don't know if our client uses the same mime version
			replacement.removeHeader("Received");	// these headers contain TLS keys
			replacement.removeHeader("X-Google-DKIM-Signature");	// custom GMail signatures etc
			replacement.removeHeader("X-Gm-Message-State");
			*/
		}

		void attach() throws MessagingException
		{
			if (mFolder != null) {
				mFolder.appendMessages(new Message[] { replacement });
				replacement.setFlag(Flags.Flag.DRAFT, false);
				replacement.setFlag(Flags.Flag.SEEN, false);
				replacement.saveChanges();
				mFolder.expunge();
			}
		}

		private static final String[] relevantHeaders = { "In-Reply-To", "Received", "Received-SPF", "X-Received", "Delivered-To", "References", "X-Gm-Message-State" };
	}
}
