{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
-- |
--
-- OAuth2 plugin for Azure AD.
--
-- * Authenticates against Azure AD
-- * Uses email as credentials identifier
--
module Yesod.Auth.OAuth2.AzureAD
    ( oauth2AzureAD
    , oauth2AzureADScoped
    ) where

import Prelude
import Yesod.Auth.OAuth2.Prelude
import Yesod.Core.Widget

newtype User = User Text

instance FromJSON User where
    parseJSON = withObject "User" $ \o -> User
        <$> o .: "mail"

pluginName :: Text
pluginName = "azuread"

defaultScopes :: [Text]
defaultScopes = ["openid", "profile"]

oauth2AzureAD :: YesodAuth m => Text -> Text -> AuthPlugin m
oauth2AzureAD = oauth2AzureADScoped defaultScopes

oauth2AzureADScoped :: YesodAuth m => [Text] -> Text -> Text -> AuthPlugin m
oauth2AzureADScoped = oauth2AzureADScopedWidget [whamlet|
        $newline never
        <p>
            <i .fa-fa-azure>
            Login via Microsoft Azure AD
    |]

oauth2AzureADScopedWidget :: YesodAuth m => WidgetFor m () -> [Text] -> Text -> Text -> AuthPlugin m
oauth2AzureADScopedWidget w scopes clientId clientSecret =
    authOAuth2Widget w pluginName oauth2 $ \manager token -> do
        (User userId, userResponse) <-
            authGetProfile pluginName manager token "https://graph.microsoft.com/v1.0/me"

        pure Creds
            { credsPlugin = pluginName
            , credsIdent = userId
            , credsExtra = setExtra token userResponse
            }
  where
    oauth2 = OAuth2
        { oauthClientId = clientId
        , oauthClientSecret = clientSecret
        , oauthOAuthorizeEndpoint = "https://login.windows.net/common/oauth2/authorize" `withQuery`
            [ scopeParam "," scopes
            , ("resource", "https://graph.microsoft.com")
            ]
        , oauthAccessTokenEndpoint = "https://login.windows.net/common/oauth2/token"
        , oauthCallback = Nothing
        }
