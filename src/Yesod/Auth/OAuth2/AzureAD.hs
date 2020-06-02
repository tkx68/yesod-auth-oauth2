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
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import URI.ByteString

newtype User = User Text

instance FromJSON User where
    parseJSON = withObject "User" $ \o -> User
        <$> o .: "mail"

pluginName :: Text
pluginName = "azuread"

defaultScopes :: [Text]
defaultScopes = ["openid", "profile"]

oauth2AzureAD :: YesodAuth m => Text -> Text -> Text -> AuthPlugin m
oauth2AzureAD = oauth2AzureADScoped defaultScopes

oauth2AzureADScoped :: YesodAuth m => [Text] -> Text -> Text -> Text -> AuthPlugin m
oauth2AzureADScoped = oauth2AzureADScopedWidget [whamlet|
        $newline never
        <button .btn.btn-social.btn-fill.btn-azure-ad>
            <i .fa.fa-azure>
            &nbsp;Login via Microsoft Azure AD
    |]

fromRight :: Either a b -> b
fromRight (Right x) = x
fromRight (Left y) = error "Argument of fromRight is not Right but Left."

oauth2AzureADScopedWidget :: YesodAuth m => WidgetFor m () -> [Text] -> Text -> Text -> Text -> AuthPlugin m
oauth2AzureADScopedWidget w scopes clientId directoryId clientSecret =
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
        , oauthClientSecret = Just clientSecret
        , oauthOAuthorizeEndpoint = (fromRight $ parseURI strictURIParserOptions (T.encodeUtf8 $ mconcat ["https://login.microsoftonline.com/", directoryId, "/oauth2/v2.0/authorize"])) `withQuery`
            [ scopeParam "," scopes
            , ("resource", "https://graph.microsoft.com")
            ]
        , oauthAccessTokenEndpoint = fromRight $ parseURI strictURIParserOptions (T.encodeUtf8 $ mconcat ["https://login.microsoftonline.com/", directoryId, "/oauth2/v2.0/token"])
        , oauthCallback = Nothing
        }
