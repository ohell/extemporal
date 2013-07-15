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

import java.io.IOException;
import java.io.PrintStream;

import asg.cliche.Command;
import asg.cliche.ShellFactory;

import org.apache.commons.cli.*;

public class Main {
	@Command
	public void simpleLocalTest()
	{
		localTest("मेरा नाम अमिताभ है", "My name is Anthony Gonsalves");
	}

	@Command
    public void localTest(String m1, String m2)
	{
		SimpleTestPlatform hakuna = new SimpleTestPlatform("Hakuna"), matata = new SimpleTestPlatform("Matata");

		PrintStream w = System.out;

		w.println("Local test commencing");
		if (m1 != null && m1.trim().length() > 0) {
			w.println("Hakuna sending message '" + m1 + "' to Matata");

			hakuna.sendMessage("Matata", m1);
			w.flush();
		}

		if (m2 != null && m2.trim().length() > 0) {
			w.println("Matata sending message '" + m2 + "' to Hakuna");
			matata.sendMessage("Hakuna", m2);
			w.flush();
		}

		hakuna.shutdown();
		matata.shutdown();
		w.println("Local test ended!");
	}

	@Command
	public void emailTest(String msg)
	{
		emailTest2(msg, null);
	}

	@Command
	public void emailTest2(String msg1, String msg2)
	{
		/*
		This test fails for 2 arguments because smtp.gmail.com ultimately refuses connection,
		maybe because there is a rate limiting policy.
		 */
		if (email1 == null || email1.length < 3 || email2 == null || email2.length < 3) {
			System.err.println("Need to run the test with email command line options e1, c1, e2 and c2");
			return;
		}

		try {	// note, we can't call shutdown() because both sending and receiving messages completes asynchronously
			if (e1 == null)
				e1 = new EmailTestPlatform(email1[0], email1[1], email1[2]);
			if (e2 == null)
				e2 = new EmailTestPlatform(email2[0], email2[1], email2[2]);

			e1.sendNewEmail(e2.mEndpoint, "Testing exTemporal library: message 1", msg1);
			if (msg2 != null && msg2.trim().length() > 0)
				e1.sendNewEmail(e2.mEndpoint, "Testing exTemporal library: message 2", msg2);
		}
		catch(Exception ex) {
			System.err.println("Oops! Something went wrong: " + ex);
			ex.printStackTrace();
		}
	}

	public static void main(String[] args) throws IOException
	{
		Options opts = new Options();
		opts.addOption(OptionBuilder.withDescription("email id for 1st account").hasArg(true).create("e1"));
		opts.addOption(OptionBuilder.withDescription("either gmail password or full URNs for Store and Transport servers").hasOptionalArgs(3).create("c1"));

		opts.addOption(OptionBuilder.withDescription("email id for 2nd account").hasArg(true).create("e2"));
		opts.addOption(OptionBuilder.withDescription("either gmail password or full URNs for Store and Transport servers").hasOptionalArgs(3).create("c2"));

		// this parses the command line but doesn't throw an exception on unknown options
		try {
			CommandLine cmd = new GnuParser().parse(opts, args, true);
			if (cmd.hasOption("e1") && cmd.hasOption("c1")) {
				String e = cmd.getOptionValue("e1");
				String[] accounts =  cmd.getOptionValues("c1");
				if (accounts.length == 1)
					email1 = EmailTestPlatform.getGMailCredentials(e, accounts[0]);
				else if (email1.length == 2) {
					email1 = new String[] { e, accounts[0], accounts[1]};
				}
			}
			if (cmd.hasOption("e2") && cmd.hasOption("c2")) {
				String e = cmd.getOptionValue("e2");
				String[] accounts =  cmd.getOptionValues("c2");
				if (accounts.length == 1)
					email2 = EmailTestPlatform.getGMailCredentials(e, accounts[0]);
				else if (email2.length == 2) {
					email2 = new String[] { e, accounts[0], accounts[1]};
				}
			}
		}
		catch (ParseException pex) {
			System.err.println("error parsing commandline: " + pex);
		}

		ShellFactory.createConsoleShell("test-harness", "Type '?list' to see valid commands", new Main()).commandLoop();
	}

	EmailTestPlatform e1, e2;
	static String[] email1, email2;
}
