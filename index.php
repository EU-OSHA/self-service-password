<?php
#==============================================================================
# LTB Self Service Password
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#==============================================================================

ob_start();

#==============================================================================
# Includes
#==============================================================================
require_once("conf/config.inc.php");
require_once("lib/vendor/defuse-crypto.phar");
require_once("lib/functions.inc.php");
if ($use_recaptcha) {
    require_once("lib/vendor/autoload.php");
}
require_once("lib/detectbrowserlanguage.php");
require_once("lib/vendor/PHPMailer/PHPMailerAutoload.php");
if ($use_pwnedpasswords) {
    require_once("lib/vendor/ron-maxweb/pwned-passwords/src/PwnedPasswords/PwnedPasswords.php");
}

#==============================================================================
# Error reporting
#==============================================================================
error_reporting(0);
if($debug) {
    error_reporting(E_ALL);
    // Important to get error details in case of SSL/TLS failure at connection
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
}

#==============================================================================
# Language
#==============================================================================
# Available languages
$languages = array();
if ($handle = opendir('lang')) {
    while (false !== ($entry = readdir($handle))) {
        if ( preg_match('/\.inc\.php$/', $entry) ) {
            $entry_lang = str_replace(".inc.php", "", $entry);
            # Only add language to possibilities if it is the default language or part of the allowed languages
            # empty $allowed_lang <=> all languages are allowed
            if ($entry_lang == $lang || empty($allowed_lang) || in_array($entry_lang, $allowed_lang) ) {
                array_push($languages, $entry_lang);
            }
        }
    }
    closedir($handle);
}
$lang = detectLanguage($lang, $languages);
require_once("lang/$lang.inc.php");
if (file_exists("conf/$lang.inc.php")) {
    require_once("conf/$lang.inc.php");
}

#==============================================================================
# PHP modules
#==============================================================================
# Init dependency check results variable
$dependency_check_results = array();

# Check PHP-LDAP presence
if ( ! function_exists('ldap_connect') ) { $dependency_check_results[] = "nophpldap"; }
else {
    # Check ldap_modify_batch presence if AD mode and password change as user
    if ( $ad_mode and $who_change_password === "user" and ! function_exists('ldap_modify_batch') ) { $dependency_check_results[] = "phpupgraderequired"; }
}

# Check PHP mhash presence if Samba mode active
if ( $samba_mode and ! function_exists('hash') and ! function_exists('mhash') ) { $dependency_check_results[] = "nophpmhash"; }

# Check PHP mbstring presence
if ( ! function_exists('mb_internal_encoding') ) { $dependency_check_results[] = "nophpmbstring"; }

# Check PHP xml presence
if ( ! function_exists('utf8_decode') ) { $dependency_check_results[] = "nophpxml"; }

# Check keyphrase setting
if ( ( ( $use_tokens and $crypt_tokens ) or $use_sms or $crypt_answers ) and ( empty($keyphrase) or $keyphrase == "secret") ) { $dependency_check_results[] = "nokeyphrase"; }
#==============================================================================
# Action
#==============================================================================
if (!isset($default_action)) { $default_action = "change"; }
if (isset($_GET["action"]) and $_GET["action"]) { $action = $_GET["action"]; }
else { $action = $default_action; }

# Available actions
$available_actions = array();
if ( $use_change ) { array_push( $available_actions, "change"); }
if ( $change_sshkey ) { array_push( $available_actions, "changesshkey"); }
if ( $use_questions ) { array_push( $available_actions, "resetbyquestions", "setquestions"); }
if ( $use_tokens ) { array_push( $available_actions, "resetbytoken", "sendtoken"); }
if ( $use_sms ) { array_push( $available_actions, "resetbytoken", "sendsms"); }

# Ensure requested action is available, or fall back to default
if ( ! in_array($action, $available_actions) ) { $action = $default_action; }

# Get source for menu
if (isset($_REQUEST["source"]) and $_REQUEST["source"]) { $source = $_REQUEST["source"]; }
else { $source="unknown"; }

#==============================================================================
# Other default values
#==============================================================================
if (!isset($ldap_login_attribute)) { $ldap_login_attribute = "uid"; }
if (!isset($ldap_fullname_attribute)) { $ldap_fullname_attribute = "cn"; }
if (!isset($pwd_forbidden_chars)) { $pwd_forbidden_chars = ""; }
if (!isset($hash_options)) { $hash_options = array(); }
if (!isset($samba_options)) { $samba_options = array(); }
if (!isset($ldap_starttls)) { $ldap_starttls = false; }

# Password policy array
$pwd_policy_config = array(
    "pwd_show_policy"         => $pwd_show_policy,
    "pwd_min_length"          => $pwd_min_length,
    "pwd_max_length"          => $pwd_max_length,
    "pwd_min_lower"           => $pwd_min_lower,
    "pwd_min_upper"           => $pwd_min_upper,
    "pwd_min_digit"           => $pwd_min_digit,
    "pwd_min_special"         => $pwd_min_special,
    "pwd_special_chars"       => $pwd_special_chars,
    "pwd_forbidden_chars"     => $pwd_forbidden_chars,
    "pwd_no_reuse"            => $pwd_no_reuse,
    "pwd_diff_login"          => $pwd_diff_login,
    "pwd_complexity"          => $pwd_complexity,
    "use_pwnedpasswords"      => $use_pwnedpasswords,
    "pwd_no_special_at_ends"  => $pwd_no_special_at_ends
);

if (!isset($pwd_show_policy_pos)) { $pwd_show_policy_pos = "above"; }
if (!isset($obscure_failure_messages)) { $obscure_failure_messages = array(); }

#==============================================================================
# Email Config
#==============================================================================
$mailer = new PHPMailer;
$mailer->Priority      = $mail_priority;
$mailer->CharSet       = $mail_charset;
$mailer->ContentType   = $mail_contenttype;
$mailer->WordWrap      = $mail_wordwrap;
$mailer->Sendmail      = $mail_sendmailpath;
$mailer->Mailer        = $mail_protocol;
$mailer->SMTPDebug     = $mail_smtp_debug;
$mailer->Debugoutput   = $mail_debug_format;
$mailer->Host          = $mail_smtp_host;
$mailer->Port          = $mail_smtp_port;
$mailer->SMTPSecure    = $mail_smtp_secure;
$mailer->SMTPAutoTLS   = $mail_smtp_autotls;
$mailer->SMTPAuth      = $mail_smtp_auth;
$mailer->Username      = $mail_smtp_user;
$mailer->Password      = $mail_smtp_pass;
$mailer->SMTPKeepAlive = $mail_smtp_keepalive;
$mailer->SMTPOptions   = $mail_smtp_options;
$mailer->Timeout       = $mail_smtp_timeout;
$mailer->LE            = $mail_newline;

#==============================================================================
?>

<html lang="<?php echo $lang ?>">
<head>
    <title><?php echo $messages["title"]; ?></title>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="author" content="LDAP Tool Box" />
    <link href="images/favicon.ico" rel="icon" type="image/x-icon" />
    <link href="images/favicon.ico" rel="shortcut icon" />

    <link rel="stylesheet" href="/load.php?debug=false&lang=en&modules=ext.addThis%7Cext.visualEditor.desktopArticleTarget.noscript%7Cmediawiki.htmlform.ooui.styles%7Cmediawiki.htmlform.styles%7Cmediawiki.legacy.commonPrint%2Cshared%7Cmediawiki.sectionAnchor%7Cmediawiki.skinning.content.externallinks%7Cmediawiki.skinning.interface%7Cmediawiki.widgets.styles%7Coojs-ui-core.styles%7Coojs-ui.styles.icons-alerts%2Cicons-content%2Cicons-interactions%2Cindicators%2Ctextures%7Cskins.osha.styles&only=styles&skin=osha" media="screen" />

    <link rel="stylesheet" href="/load.php?debug=false&lang=en&modules=ext.addThis|ext.visualEditor.desktopArticleTarget.noscript|mediawiki.htmlform.styles|mediawiki.legacy.commonPrint%2Cshared|mediawiki.sectionAnchor%2Cui|mediawiki.skinning.content.externallinks|mediawiki.skinning.interface|mediawiki.special.userlogin.common.styles|mediawiki.special.userlogin.login.styles|mediawiki.ui.button%2Ccheckbox%2Cinput%2Cradio|skins.osha.styles&only=styles&skin=osha" media="screen" />

    <link rel="stylesheet" href="/load.php?debug=false&lang=en&modules=site.styles&only=styles&skin=osha" media="screen"/>
   <style>
     #footer { height: 31px; }
   </style> 
</head>
<body class="mediawiki ltr sitedir-ltr mw-hide-empty-elt ns--1 ns-special mw-special-Userlogin page-Special_UserLogin rootpage-Special_UserLogin skin-osha action-view">
    <div id="globalWrapper">
        <div id="column-content">
		    <div id="content" class="mw-body" role="main">
	            <a id="top"></a>
	             
                <div class="mw-indicators mw-body-content">
                </div>
			    <h1 id="firstHeading" class="firstHeading" lang="en">Reset password</h1>
			    
	            <div id="bodyContent"  class="mw-body-content">
		            <div id="siteSub">From OSHWiki</div>
		            <div id="contentSub"></div>
              	    <div id="jump-to-nav" class="mw-jump">Jump to: <a href="#column-one">navigation</a>, <a href="#searchInput">search</a></div>

				    <!-- start content -->
				    <div id="mw-content-text"><div class="mw-ui-container">

                        <div class="panel-success">
                            <div class="panel-body">

                                <?php if ( $logo ) { ?>
                                    <a href="index.php" alt="Home">
                                        <img src="<?php echo $logo; ?>" alt="Logo" class="logo img-responsive center-block" />
                                    </a>
                                <?php } ?>

                                <?php
                                if ( count($dependency_check_results) > 0 ) {
                                    foreach($dependency_check_results as $result) {
                                ?>
                                    <div class="result alert alert-<?php echo get_criticity($result) ?>">
                                        <p><i class="fa fa-fw <?php echo get_fa_class($result) ?>" aria-hidden="true"></i> <?php echo $messages[$result]; ?></p>
                                    </div>
                                <?php
                                }
                                } else {
                                    include("pages/$action.php");
                                }
                                ?>

                            </div>
                        </div>

                    </div>
                    </div>
                </div>
            </div>
        </div>


        <script src="js/jquery-3.3.1.min.js"></script>
        <script src="js/bootstrap.min.js"></script>
        <script>
         $(document).ready(function(){
             // Menu links popovers
             $('[data-toggle="menu-popover"]').popover({
                 trigger: 'hover',
                 placement: 'bottom',
                 container: 'body' // Allows the popover to be larger than the menu button
             });
         });
        </script>


        <div id="column-one">
		    <h2>Navigation menu</h2>
		    <div id="p-cactions" class="portlet" role="navigation">
			    <h3>Views</h3>

			    <div class="pBody">
				    <ul>
				        <li id="ca-nstab-special" class="selected"><a href="/index.php?title=Special:UserLogin&amp;returnto=Main+Page" title="This is a special page, and it cannot be edited">Special page</a></li>
				    </ul>
			    </div>
		    </div>
		    <div class="portlet" id="p-personal" role="navigation">
			    <h3>Personal tools</h3>

			    <div class="pBody">
				    <ul>
					    <li id="pt-login"><a href="/index.php?title=Special:UserLogin&amp;returnto=Main+Page" title="You are encouraged to log in; however, it is not mandatory [o]" accesskey="o">Log in</a></li>
				</ul>
			</div>
		</div>
		<div class="portlet" id="p-logo" role="banner">
			<a href="/wiki/Main_Page" class="mw-wiki-logo" title="Visit the main page"></a>
		</div>
		<div class="generated-sidebar portlet" id="p-navigation" role="navigation">
		    <h3>Navigation</h3>
		    <div class='pBody'>
				<ul>
					<li id="n-mainpage-description"><a href="/wiki/Main_Page" title="Visit the main page [z]" accesskey="z">Main page</a></li>
					<li id="n-About-the-OSHwiki"><a href="/wiki/About">About the OSHwiki</a></li>
					<li id="n-EU-OSHA-website"><a href="http://osha.europa.eu" rel="nofollow">EU-OSHA website</a></li>
					<li id="n-OSHwiki-community"><a href="/wiki/OSHwiki_community">OSHwiki community</a></li>
					<li id="n-recentchanges"><a href="/wiki/Special:RecentChanges" title="A list of recent changes in the wiki [r]" accesskey="r">Recent changes</a></li>
					<li id="n-help"><a href="https://www.mediawiki.org/wiki/Special:MyLanguage/Help:Contents" title="The place to find out">Help</a></li>
					<li id="n-Semantic-search"><a href="/wiki/Special:Ask">Semantic search</a></li>
				</ul>
			</div>
		</div>
		<div class="generated-sidebar portlet" id="p-articles" role="navigation">
		    <h3>articles</h3>
		    <div class='pBody'>
				<ul>
					<li id="n-Create-new-article"><a href="/wiki/ArticleForms">Create new article</a></li>
					<li id="n-Table-of-Contents"><a href="/wiki/Table_of_Contents">Table of Contents</a></li>
					<li id="n-New-Pages"><a href="/wiki/NewPages">New Pages</a></li>
				</ul>
			</div>
		</div>
		<div id="p-search" class="portlet" role="search">
			<h3><label for="searchInput">Search</label></h3>

			<div id="searchBody" class="pBody">
				<form action="/index.php" id="searchform">
					<input type='hidden' name="title" value="Special:Search"/>
					<input type="search" name="search" placeholder="Search OSHWiki" title="Search OSHWiki [f]" accesskey="f" id="searchInput"/>
					<input type="submit" name="go" value="Go" title="Go to a page with this exact name if it exists" id="searchGoButton" class="searchButton"/>&#160;
					<input type="submit" name="fulltext" value="Search" title="Search the pages for this text" id="mw-searchButton" class="searchButton"/>
				</form>

			</div>
		</div>
		<div class="portlet" id="p-tb" role="navigation">
			<h3>Tools</h3>

			<div class="pBody">
				<ul>
					<li id="t-specialpages"><a href="/wiki/Special:SpecialPages" title="A list of all special pages [q]" accesskey="q">Special pages</a></li>
					<li id="t-print"><a href="/index.php?title=Special:UserLogin&amp;returnto=Main+Page&amp;printable=yes" rel="alternate" title="Printable version of this page [p]" accesskey="p">Printable version</a></li>
				</ul>
			</div>
		</div>
	</div><!-- end of the left (by default at least) column -->
	<div class="visualClear"></div>


    <div id="footer" role="contentinfo">
	    <div id="f-poweredbyico"><a href="http://www.mediawiki.org/"><img src="/resources/assets/poweredby_mediawiki_88x31.png" height="31" width="88" alt="Powered by MediaWiki" /></a>
            <a href="https://www.semantic-mediawiki.org/wiki/Semantic_MediaWiki"><img src="data:image/png;base64,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" alt="Powered by Semantic MediaWiki" width="88" height="31"/></a></div>
	    <ul id="f-list">
		    <li id="privacy"><a href="/wiki/OSHWiki:Privacy_policy" title="OSHWiki:Privacy policy">Privacy policy</a></li>
		    <li id="about"><a href="/wiki/OSHWiki:About" title="OSHWiki:About">About OSHWiki</a></li>
		    <li id="disclaimer"><a href="/wiki/OSHWiki:General_disclaimer" title="OSHWiki:General disclaimer">Disclaimers</a></li>
	    </ul>
    </div>
    </div>

</div>
</body>
</html>
<?php

ob_end_flush();
