# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright (c) 2016-2017 Anaconda, Inc.
#
# May be copied and distributed freely only as part of an Anaconda or
# Miniconda installation.
# -----------------------------------------------------------------------------
"""Anaconda Cloud login dialog."""

# yapf: disable

from __future__ import absolute_import, division, print_function

# Standard library imports
import ast
import json
from collections import namedtuple

# Third party imports
from qtpy.QtCore import QRegExp, Qt, QUrl, Signal
from qtpy.QtGui import QDesktopServices, QRegExpValidator, QPixmap
from qtpy.QtWidgets import QApplication, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget, QGridLayout

from conda_token.repo_config import CondaTokenError, validate_token, token_set

# Local imports
from anaconda_navigator.utils import get_domain_from_api_url
from anaconda_navigator.api.anaconda_api import AnacondaAPI
from anaconda_navigator.config import CONF
from anaconda_navigator.static.fonts import load_fonts
from anaconda_navigator.utils.analytics import GATracker
from anaconda_navigator.utils.styles import load_style_sheet
from anaconda_navigator.widgets import ButtonNormal, ButtonPrimary, FrameBase
from anaconda_navigator.widgets.dialogs import StaticDialogBase, LabelBase, MessageBoxInformation
from anaconda_navigator.widgets.manager.channels import SelectableChannelsListTable
from anaconda_navigator.static.images import (
    ANACONDA_TEAM_EDITION_LOGIN_LOGO, ANACONDA_ENTERPRISE_EDITION_LOGIN_LOGO,
    ANACONDA_ORG_EDITION_LOGIN_LOGO, ANACONDA_COMMERCIAL_EDITION_LOGIN_LOGO)


# yapf: enable

USER_RE = QRegExp(r'^[A-Za-z0-9_\.][A-Za-z0-9_\.\-]+$')
FORGOT_USERNAME_URL = 'account/forgot_username'
FORGOT_PASSWORD_URL = 'account/forgot_password'


TextContainer = namedtuple('TextContainer', (
    'info_frame_text',
    'forgot_links_msg',
    'form_main_text',
    'form_secondary_text',
    'form_input_label_text',
    'form_button_text',
    'message_box_error_text',
    'logo_path'))
TextContainer.__new__.__defaults__ = (None,) * len(TextContainer._fields)

ANACONDA_LOGIN_TEXT_CONTAINER = TextContainer(
    info_frame_text='Log into Anaconda.org to access private channels and packages. If you don’t have an account,'
                    ' click <a href="{}" style="color:#43B049;text-decoration: none">here</a>.',
    forgot_links_msg='Forget your <a href="{username_url}" style="color:#43B049; text-decoration:none">username</a> or '
                     '<a href="{password_url}" style="color:#43B049; text-decoration:none">password</a>?',
    message_box_error_text='The Anaconda.Org API domain is not specified! Please, set in preferences.',
    logo_path=ANACONDA_ORG_EDITION_LOGIN_LOGO
)

ENTERPRISE_LOGIN_TEXT_CONTAINER = TextContainer(
    info_frame_text='Login to configure Conda and Navigator to install packages'
                    ' from your on-premise package repository.',
    message_box_error_text='The Enterprise 4 Repository API domain is not specified! Please, set in preferences.',
    logo_path=ANACONDA_ENTERPRISE_EDITION_LOGIN_LOGO,
)

TEAM_LOGIN_TEXT_CONTAINER = TextContainer(
    logo_path=ANACONDA_TEAM_EDITION_LOGIN_LOGO,
    info_frame_text='Login to configure Conda and Navigator to install packages from your Team Edition instance.',
    message_box_error_text='The Team Edition API domain is not specified! Please, set in preferences.'
)

COMMERCIAL_LOGIN_TEXT_CONTAINER = TextContainer(
    form_main_text='Looks like this is the first time you are logging into Commercial Edition. '
                   'Please set your unique access token.',
    form_secondary_text='You only need to set this token once. You can always change this in your Preferences.',
    form_input_label_text='Enter Commercial Edition Token',
    form_button_text='Set Token',
    logo_path=ANACONDA_COMMERCIAL_EDITION_LOGIN_LOGO,
    info_frame_text='Configure Conda and Navigator to install packages from the open-source distribution optimized '
                    'for commercial use and compliance with our '
                    '<a href="https://www.anaconda.com/terms-of-service" '
                    'style="color:#43B049;text-decoration: none">Terms of Service</a>. '
                    'Subscription required. More details '
                    '<a href="https://www.anaconda.com/products/commercial-edition" '
                    'style="color:#43B049;text-decoration: none">here</a>.'
)

ENTERPRISE_SET_DOMAIN_TEXT_CONTAINER = TextContainer(
    form_main_text='Looks like this is the first time you are logging into Enterprise 4 Repository. '
                   'Please set your Enterprise 4 Repository API domain.',
    form_secondary_text='You only need to set this domain once. You can always change this in your Preferences.',
    form_input_label_text='Enter Enterprise 4 Repository API Domain',
    form_button_text='Set Domain',
    logo_path=ANACONDA_ENTERPRISE_EDITION_LOGIN_LOGO,
    info_frame_text="Login to configure Conda and Navigator to install"
                    " packages from your on-premise package repository."
)

TEAM_SET_DOMAIN_TEXT_CONTAINER = TextContainer(
    form_main_text='Looks like this is the first time you are logging into Team Edition. '
                   'Please set your Team Edition domain.',
    form_secondary_text='You only need to set this domain once. You can always change this in your Preferences.',
    form_input_label_text='Team Edition Domain',
    form_button_text='Set Domain',
    logo_path=ANACONDA_TEAM_EDITION_LOGIN_LOGO,
    info_frame_text="Login to configure Conda and Navigator "
                    "to install packages from your Team Edition instance."
)


class LabelMainLoginTitle(LabelBase):
    """Label used in CSS styling."""


class LabelMainLoginText(LabelBase):
    """Label used in CSS styling."""


class LabelMainLoginSubTitle(LabelBase):
    """Label used in CSS styling."""


class WidgetLoginInfoFrame(FrameBase):
    """Widget used in CSS styling."""


class WidgetLoginFormFrame(FrameBase):
    """Widget used in CSS styling."""


class WidgetLoginCardsFrame(FrameBase):
    """Widget used in CSS styling."""


class WidgetLoginPageContent(FrameBase):
    """Widget used in CSS styling."""


class SecondaryButton(ButtonNormal):
    """Label used in CSS styling."""


class WidgetLoginCard(FrameBase):
    """Widget used in CSS styling."""


class LabelLoginLogo(LabelBase):
    """Label used in CSS styling."""


class BasePage(StaticDialogBase):

    def __init__(self, *args, **kwargs):
        super(BasePage, self).__init__(*args, **kwargs)

    @property
    def username(self):
        """Return the logged username."""
        return self.text_username.text().lower()

    def _get_info_frame(self):
        label_icon = LabelLoginLogo()
        label_icon.setPixmap(QPixmap(self.text_container.logo_path))
        label_icon.setScaledContents(True)  # important on High DPI!
        label_icon.setAlignment(Qt.AlignLeft)

        self.label_information = QLabel(self.text_container.info_frame_text)
        self.label_information.setWordWrap(True)

        self.button_back = SecondaryButton('Back to select screen')

        info_widget = WidgetLoginInfoFrame()
        info_layout = QVBoxLayout()
        info_layout.addWidget(label_icon)
        info_layout.addWidget(self.label_information)
        info_layout.addWidget(self.button_back)
        info_widget.setLayout(info_layout)

        return info_widget

    def _get_forgot_links_widget(self):
        self.forgot_username_url = None
        self.forgot_password_url = None

        forgot_links_widget = QWidget()
        forgot_layout = QHBoxLayout()
        self.forgot_links = QLabel(self.text_container.forgot_links_msg)
        forgot_layout.addWidget(self.forgot_links, 0, Qt.AlignLeft)
        forgot_layout.addStretch(100000000)
        forgot_links_widget.setLayout(forgot_layout)

        return forgot_links_widget

    def open_url(self, url):
        """Open given url in the default browser and log the action."""
        self.tracker.track_event('content', 'click', url)
        QDesktopServices.openUrl(QUrl(url))

    def update_style_sheet(self, style_sheet=None):
        """Update custom css style sheet."""
        if style_sheet is None:
            style_sheet = load_style_sheet()
        self.setStyleSheet(style_sheet)

    def back_to_select_screen(self):
        self.reject()
        self.main_dialog.show()


class BaseLoginPage(BasePage):
    def __init__(self, anaconda_api, main_dialog, text_container):
        super(BaseLoginPage, self).__init__(parent=main_dialog.parent)
        self.text_container = text_container

        self.token = None
        self.error = None
        self.config = CONF
        self.anaconda_api = anaconda_api
        self.main_dialog = main_dialog
        self.tracker = GATracker()

        forgot_links_widget = self._get_forgot_links_widget() if self.text_container.forgot_links_msg else None
        login_form_widget = self._get_form_frame(forgot_links_widget)
        info_widget = self._get_info_frame()

        main_layout = QVBoxLayout()
        body_page_widget = WidgetLoginPageContent()
        body_layout = QHBoxLayout()

        title = LabelMainLoginTitle("Sign in to access your repository")
        title.setWordWrap(True)
        main_layout.addWidget(title)
        body_layout.addWidget(info_widget)
        body_layout.addWidget(login_form_widget)
        body_page_widget.setLayout(body_layout)
        main_layout.addWidget(body_page_widget)
        self.setLayout(main_layout)

        self.text_username.textEdited.connect(self.check_text)
        self.text_password.textEdited.connect(self.check_text)
        self.button_login.clicked.connect(self.login)
        self.button_back.clicked.connect(self.back_to_select_screen)

        self.check_text()
        self.update_style_sheet()
        self.text_username.setFocus()

    def check_text(self):
        """Check that `username` and `password` are not empty strings.

        If not empty and disable/enable buttons accordingly.
        """
        username = self.text_username.text()
        password = self.text_password.text()

        if not all((len(username), len(password))):
            self.button_login.setDisabled(True)
        else:
            self.button_login.setDisabled(False)

    def login(self):
        api_url = self.config.get('main', self.api_url_config_option)
        if not api_url:
            msg_box = MessageBoxInformation(
                title='Login Error',
                text=self.text_container.domain_not_found_msg,
            )
            msg_box.exec_()

            self.button_login.setDisabled(False)
            self.check_text()
            QApplication.restoreOverrideCursor()
            return

        username_text = self.text_username.text().lower()
        self.button_login.setEnabled(False)
        self.label_message.setText('')
        self.text_username.setText(username_text)

        QApplication.setOverrideCursor(Qt.WaitCursor)

        # Reload the client to the other one, if needed.
        self.config.set('main', 'logged_api_url', api_url)
        self.anaconda_api.client_reload()

        worker = self.anaconda_api.login(username_text, self.text_password.text())
        worker.sig_finished.connect(self._finished)

    def _finished(self, worker, output, error):
        """
        Callback for the login procedure after worker has finished.

        If success, sets the token, 'username' attribute to parent widget
        and sends the accept signal.

        Otherwise, outputs error messages.
        """
        token = output
        username = self.text_username.text().lower()

        if token:
            self.token = token
            self.sig_authentication_succeeded.emit()
            self.main_dialog.username = username
            self.accept()
            self.main_dialog.accept()

        elif error:
            bold_username = '<b>{0}</b>'.format(username)

            # The error might come in (error_message, http_error) format
            try:
                error_message = ast.literal_eval(str(error))[0]
            except Exception:  # pragma: no cover
                error_message = str(error)

            error_message = error_message.lower().capitalize()
            error_message = error_message.split(', ')[0]
            error_text = '<i>{0}</i>'.format(error_message)
            error_text = error_text.replace(username, bold_username)
            self.label_message.setText(error_text)
            self.label_message.setVisible(True)

            if error_message:
                domain = self.anaconda_api.client_domain()
                label = '{0}/{1}: {2}'.format(domain, username, error_message.lower())
                self.tracker.track_event('authenticate', 'login failed', label=label)
                self.text_password.setFocus()
                self.text_password.selectAll()
            self.sig_authentication_failed.emit()

        self.button_login.setDisabled(False)
        self.check_text()
        QApplication.restoreOverrideCursor()

    def _get_form_frame(self, forgot_links_widget=None):
        self.label_username = QLabel('Username:')
        self.label_password = QLabel('Password:')
        self.text_username = QLineEdit()
        self.text_password = QLineEdit()
        self.label_message = LabelMainLoginText('')
        self.label_message.setWordWrap(True)

        self.text_username.setValidator(QRegExpValidator(USER_RE))
        self.text_password.setEchoMode(QLineEdit.Password)
        self.label_message.setVisible(False)

        self.button_login = ButtonPrimary('Sign In')
        self.button_login.setDefault(True)

        login_form_widget = WidgetLoginFormFrame()
        login_form_layout = QVBoxLayout()
        for widget in (self.label_username, self.text_username,
                       self.label_password, self.text_password, self.label_message):
            login_form_layout.addWidget(widget)

        if forgot_links_widget:
            login_form_layout.addWidget(forgot_links_widget)

        login_form_layout.addWidget(self.button_login, 0, Qt.AlignHCenter)
        login_form_widget.setLayout(login_form_layout)

        return login_form_widget


class BaseSettingPage(BasePage):
    def __init__(self, anaconda_api, main_dialog, text_container):

        super(BaseSettingPage, self).__init__(parent=main_dialog.parent)

        self.config = CONF
        self.text_container = text_container
        self.anaconda_api = anaconda_api
        self.main_dialog = main_dialog
        self.tracker = GATracker()

        info_widget = self._get_info_frame()
        login_form_widget = self._get_form_frame()

        title = LabelMainLoginTitle("Sign in to access your repository")
        title.setWordWrap(True)

        body_layout = QHBoxLayout()
        body_layout.addWidget(info_widget)
        body_layout.addWidget(login_form_widget)

        body_page_widget = WidgetLoginPageContent()
        body_page_widget.setLayout(body_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(title)
        main_layout.addWidget(body_page_widget)
        self.setLayout(main_layout)

        self.button_back.clicked.connect(self.back_to_select_screen)
        self.label_information.linkActivated.connect(lambda activated_link: self.open_url(activated_link))

        self.update_style_sheet()
        self.input_line.setFocus()

    def _get_form_frame(self):
        self.label_text = LabelMainLoginText(self.text_container.form_main_text)
        self.label_note = LabelMainLoginSubTitle(self.text_container.form_secondary_text)
        self.input_label = QLabel(self.text_container.form_input_label_text)
        self.label_text.setWordWrap(True)
        self.label_note.setWordWrap(True)

        self.input_line = QLineEdit()

        self.label_message = LabelMainLoginText('')
        self.label_message.setWordWrap(True)
        self.label_message.setVisible(False)

        self.button_apply = ButtonPrimary(self.text_container.form_button_text)
        self.button_apply.setEnabled(True)
        self.button_apply.setDefault(True)

        login_form_widget = WidgetLoginFormFrame()
        login_form_layout = QVBoxLayout()
        for widget in (self.label_text, self.label_note, self.input_label, self.input_line, self.label_message):
            login_form_layout.addWidget(widget)
        login_form_layout.addWidget(self.button_apply, 0, Qt.AlignHCenter)
        login_form_widget.setLayout(login_form_layout)

        return login_form_widget

    def set_domain(self):
        self.input_line.setText(self.input_line.text().lower())
        self.label_message.setText('')

        if self.check_text():
            self.config.set('main', self.api_url_config_option, self.input_line.text().strip('/'))
            self.anaconda_api.client_reload()
            self.accept()
            self.main_dialog.sig_update_card_handler.emit(self.api_url_config_option)
            login_page = self.next_dialog_factory(AnacondaAPI(), self.main_dialog)
            self.main_dialog.sig_login_type_clicked.emit(login_page)

        QApplication.restoreOverrideCursor()

    def check_text(self, text=None):
        text = text or self.input_line.text()
        valid, error = self.is_valid_api(text.lower())

        if not valid:
            self.label_message.setText(error)
            self.label_message.setVisible(bool(self.input_line.text()))
            return False

        self.button_apply.setEnabled(True)
        self.label_message.setVisible(False)

        return True

    def is_valid_api(self, url, verify=True, allow_blank=False):
        """Check if a given URL is a valid anaconda api endpoint."""

        valid = self.anaconda_api.download_is_valid_api_url(
            url, non_blocking=False, verify=verify, allow_blank=allow_blank
        )
        error = ''
        if not valid:
            error = 'Invalid API url. Check the url is valid and corresponds to the api endpoint.'
        return valid, error


class CommercialEditionLoginPage(BaseSettingPage):

    def __init__(self, anaconda_api, main_dialog):

        super(CommercialEditionLoginPage, self).__init__(anaconda_api, main_dialog, COMMERCIAL_LOGIN_TEXT_CONTAINER)

        self.button_apply.clicked.connect(self.set_token)
        self.input_line.setEchoMode(QLineEdit.Password)

    def set_token(self):
        ce_token = self.input_line.text()
        self.label_message.setText('')

        if self.check_text():
            token_set(ce_token)
            commercial_edition_url = self.config.get('main', 'commercial_edition_url')
            self.config.set('main', 'logged_api_url', commercial_edition_url)
            self.anaconda_api.client_reload()
            self.accept()
            self.main_dialog.accept()

        QApplication.restoreOverrideCursor()

    def check_text(self):
        try:
            validate_token(self.input_line.text())
        except CondaTokenError as e:
            self.label_message.setText(str(e))
            self.label_message.setVisible(bool(self.input_line.text()))
            return False

        self.button_apply.setEnabled(True)
        self.label_message.setVisible(False)

        return True


class TeamEditionSetDomainPage(BaseSettingPage):

    def __init__(self, anaconda_api, main_dialog):
        super(TeamEditionSetDomainPage, self).__init__(anaconda_api, main_dialog, TEAM_SET_DOMAIN_TEXT_CONTAINER)
        self.api_url_config_option = 'team_edition_api_url'
        self.next_dialog_factory = TeamEditionLoginPage
        self.input_line.setPlaceholderText('http(s)://example.com')
        self.button_apply.clicked.connect(self.set_domain)

    def check_text(self, text=None):
        text = text or self.input_line.text()
        domain = get_domain_from_api_url(text)
        self.input_line.setText(domain)
        return super(TeamEditionSetDomainPage, self).check_text(text='{}/api/system'.format(domain))


class TeamEditionLoginPage(BaseLoginPage):
    sig_authentication_succeeded = Signal()
    sig_authentication_failed = Signal()

    def __init__(self, anaconda_api, main_dialog):
        super(TeamEditionLoginPage, self).__init__(anaconda_api, main_dialog, TEAM_LOGIN_TEXT_CONTAINER)
        self.api_url_config_option = 'team_edition_api_url'

    def _finished(self, worker, output, error):
        """
        Callback for the login procedure after worker has finished.

        If success, sets the token, 'username' attribute to parent widget
        and sends the accept signal.

        Otherwise, outputs error messages.
        """
        try:
            response = json.loads(output)

            if 'token' in response and 'refresh_token' in response:
                self.main_dialog.username = self.username
                self.token = output
                self.accept()
                te_channels = TeamEditionAddChannelsPage(self.anaconda_api, self.main_dialog, self)
                te_channels.open()

            else:
                if 'message' in response and response['message'] == 'Unauthorized':
                    self.label_message.setText('<i>Invalid Credentials!</i>')
                elif 'message' in response:
                    self.label_message.setText('<i>{}</i>'.format(response['message']))

                self.label_message.setVisible(True)
                self._track_error(output)

        except (json.decoder.JSONDecodeError, TypeError):
            self.label_message.setText('<i>Unhandled error happened!</i>')
            self.label_message.setVisible(True)
            self._track_error(error)

        self.button_login.setDisabled(False)
        self.check_text()
        QApplication.restoreOverrideCursor()

    def _track_error(self, error):
        domain = self.anaconda_api.client_domain()
        label = '{0}/{1}: {2}'.format(domain, self.username, str(error).lower())
        self.tracker.track_event('authenticate', 'login failed', label=label)
        self.text_password.setFocus()
        self.text_password.selectAll()


class TeamEditionAddChannelsPage(BasePage):
    def __init__(
            self,
            anaconda_api,
            main_dialog=None,
            parent=None,
            msg='Select default channels to be used',
            btn_add_msg='Add Channels'
    ):
        super(TeamEditionAddChannelsPage, self).__init__(main_dialog.parent if main_dialog else parent)

        self.config = CONF
        self.anaconda_api = anaconda_api
        self.main_dialog = main_dialog
        self.parent = parent
        self.tracker = GATracker()

        QApplication.restoreOverrideCursor()
        pixmap = QPixmap(ANACONDA_TEAM_EDITION_LOGIN_LOGO)
        pixmap = pixmap.scaledToWidth(200, Qt.SmoothTransformation)
        label_icon = LabelLoginLogo()
        label_icon.setPixmap(pixmap)
        label_icon.setAlignment(Qt.AlignLeft)
        self.label_information = QLabel(msg)

        rc_data = self.anaconda_api._conda_api.load_rc()

        api_channels_data = self.anaconda_api.get_channels()
        channels = rc_data.get('channels', [])
        default_channels = rc_data.get('default_channels', [])

        self.channels_table = SelectableChannelsListTable(
            self, table_data=api_channels_data, channels=channels, default_channels=default_channels
        )
        self.channels_table.setMaximumWidth(650)

        self.button_skip = SecondaryButton('Skip')
        self.button_add = ButtonPrimary(btn_add_msg)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.button_skip)
        buttons_layout.addWidget(self.button_add)

        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(label_icon, Qt.AlignLeft)
        self.main_layout.addWidget(self.label_information, Qt.AlignRight)
        self.main_layout.addWidget(self.channels_table, Qt.AlignCenter)
        self.main_layout.addLayout(buttons_layout)

        self.setLayout(self.main_layout)

        self.button_skip.clicked.connect(self.skip)
        self.button_add.clicked.connect(self.add_channels)
        self.button_close_dialog.clicked.connect(self.close_window)

    def skip(self):
        self.anaconda_api.create_login_data()
        self.close_window()

    def add_channels(self):
        default_channels, channels = self.channels_table.get_selected_channels()

        if not default_channels:
            self.label_information.setText(
                'At least one channel should be added to <b>default_channels</b>! Please add...'
            )
        else:
            self.anaconda_api.create_login_data(default_channels, channels)
            self.close_window()

    def close_window(self):
        try:
            self.parent.accept()
            self.main_dialog.accept()
        except AttributeError:
            self.parent.sig_logged_in.emit()

        self.accept()


class EnterpriseRepoSetDomainPage(BaseSettingPage):
    def __init__(self, anaconda_api, main_dialog):
        """Login dialog."""

        super(EnterpriseRepoSetDomainPage, self).__init__(
            anaconda_api, main_dialog, ENTERPRISE_SET_DOMAIN_TEXT_CONTAINER)
        self.api_url_config_option = 'enterprise_4_repo_api_url'
        self.next_dialog_factory = EnterpriseRepoLoginPage
        self.input_line.setPlaceholderText('http(s)://example.com')
        self.button_apply.clicked.connect(self.set_domain)


class EnterpriseRepoLoginPage(BaseLoginPage):

    sig_authentication_succeeded = Signal()
    sig_authentication_failed = Signal()

    def __init__(self, anaconda_api, main_dialog):
        """Login dialog."""

        super(EnterpriseRepoLoginPage, self).__init__(anaconda_api, main_dialog, ENTERPRISE_LOGIN_TEXT_CONTAINER)
        self.api_url_config_option = 'enterprise_4_repo_api_url'


class AnacondaLoginPage(BaseLoginPage):
    sig_authentication_succeeded = Signal()
    sig_authentication_failed = Signal()

    def __init__(self, anaconda_api, main_dialog):
        """Login dialog."""

        super(AnacondaLoginPage, self).__init__(anaconda_api, main_dialog, ANACONDA_LOGIN_TEXT_CONTAINER)
        self.api_url_config_option = 'anaconda_api_url'
        self.update_links()

    def update_links(self):
        """Update links."""

        anaconda_api_url = self.config.get('main', 'anaconda_api_url', self.anaconda_api.client_get_api_url())
        if not anaconda_api_url:
            return

        base_url = anaconda_api_url.lower().replace('//api.', '//')

        parts = base_url.lower().split('/')
        base_url = '/'.join(parts[:-1]) if parts[-1] == 'api' else base_url

        forgot_links_updated_text = self.forgot_links.text().format(
            username_url=base_url + '/' + FORGOT_USERNAME_URL,
            password_url=base_url + '/' + FORGOT_PASSWORD_URL
        )
        info_updated_text = self.label_information.text().format(base_url)
        self.label_information.setText(info_updated_text)
        self.forgot_links.setText(forgot_links_updated_text)

        self.label_information.linkActivated.connect(lambda activated_link: self.open_url(activated_link))
        self.forgot_links.linkActivated.connect(lambda activated_link: self.open_url(activated_link))


class LoginCard(QWidget):
    def __init__(
        self,
        description=None,
        image_path=None,
        login_page=None,
        login_signal=None,
    ):
        """Item with custom widget for the applications list."""
        super(LoginCard, self).__init__()
        self.login_page = login_page

        self.api = AnacondaAPI()
        self.description = description
        self.image_path = image_path
        self.style_sheet = None

        self.button_login = SecondaryButton("SIGN IN")
        self.label_description = QLabel(self.description)

        self.label_icon = LabelLoginLogo()
        self.pixmap = QPixmap(self.image_path)

        self.label_icon.setPixmap(self.pixmap)
        self.label_icon.setScaledContents(True)  # important on High DPI!
        self.label_icon.setMaximumWidth(200)
        self.label_icon.setMaximumHeight(52)
        self.label_icon.setAlignment(Qt.AlignLeft)

        self.label_description.setWordWrap(True)
        self.label_description.setAlignment(Qt.AlignLeft)

        body_widget = WidgetLoginCard()
        layout_main = QVBoxLayout()
        layout_body = QVBoxLayout()
        layout_body.addWidget(self.label_icon, 0, Qt.AlignLeft)
        layout_body.addWidget(self.label_description, 0, Qt.AlignLeft)
        layout_body.addWidget(self.button_login, 0, Qt.AlignRight)

        body_widget.setLayout(layout_body)

        layout_main.addWidget(body_widget)
        self.setLayout(layout_main)

        self.button_login.clicked.connect(lambda: login_signal.emit(self.login_page))


class MainLoginDialog(StaticDialogBase):
    sig_login_type_clicked = Signal(object)
    sig_update_card_handler = Signal(str)

    def __init__(self, parent=None):
        """Login dialog."""

        super(MainLoginDialog, self).__init__(parent)
        self.parent = parent

        self.username = None

        title = LabelMainLoginTitle("Sign in to access your repository")
        title.setWordWrap(True)

        description = LabelMainLoginText(
            "Connect to your repository to enable powerful collaboration"
            " and package management for open-source and private projects."
        )
        description.setWordWrap(True)

        subtitle = LabelMainLoginSubTitle("Connect to your Repository")
        subtitle.setWordWrap(True)

        grid_widget = WidgetLoginCardsFrame()
        grid = QGridLayout()

        self.anaconda_client_login_card = LoginCard(
            description="Log into Anaconda.org to access private channels and packages.",
            image_path=ANACONDA_ORG_EDITION_LOGIN_LOGO,
            login_page=AnacondaLoginPage(AnacondaAPI(), self),
            login_signal=self.sig_login_type_clicked
        )
        self.team_edition_login_card = LoginCard(
            description="Login to configure Conda and Navigator to "
            "install packages from your on-premise package repository.",
            image_path=ANACONDA_TEAM_EDITION_LOGIN_LOGO,
            login_page=self._get_team_edition_page(),
            login_signal=self.sig_login_type_clicked
        )
        self.commercial_edition_login_card = LoginCard(
            description="Configure Conda and Navigator to install packages from the open-source distribution optimized "
            "for commercial use and compliance with our Terms of Service.",
            image_path=ANACONDA_COMMERCIAL_EDITION_LOGIN_LOGO,
            login_page=CommercialEditionLoginPage(AnacondaAPI(), self),
            login_signal=self.sig_login_type_clicked
        )
        self.enterprise_edition_login_card = LoginCard(
            description="Login to configure Conda and Navigator to "
            "install packages from your on-premise package repository.",
            image_path=ANACONDA_ENTERPRISE_EDITION_LOGIN_LOGO,
            login_page=self._get_enterprise_page(),
            login_signal=self.sig_login_type_clicked
        )

        grid.addWidget(self.anaconda_client_login_card, 1, 1)
        grid.addWidget(self.team_edition_login_card, 1, 2)
        grid.addWidget(self.commercial_edition_login_card, 2, 1)
        grid.addWidget(self.enterprise_edition_login_card, 2, 2)
        grid_widget.setLayout(grid)

        main_layout = QVBoxLayout()
        main_layout.addWidget(title)
        main_layout.addWidget(description)
        main_layout.addWidget(subtitle)
        main_layout.addWidget(grid_widget)
        self.setLayout(main_layout)

        self.sig_login_type_clicked.connect(self.login_page_selected)
        self.sig_update_card_handler.connect(self.update_card_handler)

    def _get_enterprise_page(self):
        enterprise_api_url = CONF.get('main', 'enterprise_4_repo_api_url')
        return EnterpriseRepoLoginPage(AnacondaAPI(), self) if enterprise_api_url \
            else EnterpriseRepoSetDomainPage(AnacondaAPI(), self)

    def _get_team_edition_page(self):
        team_edition_api_url = CONF.get('main', 'team_edition_api_url')
        if team_edition_api_url:
            return TeamEditionLoginPage(AnacondaAPI(), self)

        return TeamEditionSetDomainPage(AnacondaAPI(), self)

    def login_page_selected(self, login_page):
        if not self.isHidden():
            self.hide()
        login_page.open()

    def update_card_handler(self, domain_url_key):
        if domain_url_key == 'enterprise_4_repo_api_url':
            self.enterprise_edition_login_card.login_page = EnterpriseRepoLoginPage(AnacondaAPI(), self)
        elif domain_url_key == 'team_edition_api_url':
            self.team_edition_login_card.login_page = TeamEditionLoginPage(AnacondaAPI(), self)


# --- Local testing
# -----------------------------------------------------------------------------
def local_test():  # pragma: no cover
    """Run local test."""
    from anaconda_navigator.utils.qthelpers import qapplication
    app = qapplication(test_time=3)
    load_fonts(app)
    widget = MainLoginDialog()
    widget.show()
    app.exec_()


if __name__ == '__main__':  # pragma: no cover
    local_test()
