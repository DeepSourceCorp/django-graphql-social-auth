import graphene
from calendar import timegm
from datetime import datetime

import graphene
import graphql_jwt
from django.utils import timezone
from graphql_jwt.settings import jwt_settings


class SocialAuthMixin:

    @classmethod
    def __init_subclass_with_meta__(cls, name=None, **options):
        assert getattr(cls, 'resolve', None), (
            '{name}.resolve method is required in a SocialAuthMutation.'
        ).format(name=name or cls.__name__)

        super().__init_subclass_with_meta__(name=name, **options)


class ResolveMixin:

    @classmethod
    def resolve(cls, *args, **kwargs):
        return cls()


class JSONWebTokenMixin:
    token = graphene.String()
    refresh_token = graphene.String()
    token_expires_in = graphene.Int()
    refresh_expires_in = graphene.Int()

    @staticmethod
    def resolve_refresh_token(social_auth, info):
        refresh_token = graphql_jwt.refresh_token.shortcuts.create_refresh_token(
            social_auth.social.user
        )
        info.context.jwt_refresh_token = refresh_token
        return refresh_token.get_token()

    @staticmethod
    def resolve_refresh_expires_in(*_args, **_kwargs):
        refresh_expires_in = (
            timegm(datetime.utcnow().utctimetuple())
            + jwt_settings.JWT_REFRESH_EXPIRATION_DELTA.total_seconds()
        )
        return refresh_expires_in

    @staticmethod
    def resolve_token_expires_in(*_args, **_kwargs):
        return int((timezone.now() + jwt_settings.JWT_EXPIRATION_DELTA).timestamp())

    @classmethod
    def resolve(cls, root, info, social, **kwargs):
        try:
            from graphql_jwt.shortcuts import get_token
        except ImportError:
            raise ImportError(
                'django-graphql-jwt not installed.\n'
                "Use `pip install 'django-graphql-social-auth[jwt]'`.")

        return cls(token=get_token(social.user))
