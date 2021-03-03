from functools import wraps

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from promise import Promise, is_thenable
from social_core.exceptions import MissingBackend
from social_django.utils import psa as _psa, STORAGE, get_strategy
from social_django.views import _do_login

from . import exceptions, mixins


def load_strategy(request=None):
    return get_strategy("graphql_social_auth.strategy.GrapheneStrategy", STORAGE, request)


@_psa(load_strategy=load_strategy)
def decorate_request(request, backend):
    pass


def psa(f):
    @wraps(f)
    def wrapper(cls, root, info, provider, code, **kwargs):
        request = info.context
        request.auth_data = {"code": [code], "provider": [provider]}
        try:
            decorate_request(request, provider)
        except MissingBackend:
            raise exceptions.GraphQLSocialAuthError(_('Provider not found'))
        if request.user.is_authenticated:
            authenticated_user = request.user
        else:
            authenticated_user = None
        request.backend.redirect_uri = request.build_absolute_uri(settings.CALLBACK_URLS[provider])
        request.backend.REDIRECT_STATE = False
        request.backend.STATE_PARAMETER = False
        user = request.backend.complete(user=authenticated_user)

        if user is None:
            raise exceptions.InvalidTokenError(_('Invalid token'))

        user_model = request.backend.strategy.storage.user.user_model()

        if not isinstance(user, user_model):
            msg = _('`{}` is not a user instance').format(type(user).__name__)
            raise exceptions.DoAuthError(msg, user)

        if not issubclass(cls, mixins.JSONWebTokenMixin):
            _do_login(request.backend, user, user.social_user)

        return f(cls, root, info, user.social_user, **kwargs)
    return wrapper


def social_auth(f):
    @psa
    @wraps(f)
    def wrapper(cls, root, info, social, **kwargs):
        def on_resolve(payload):
            payload.social = social
            return payload

        result = f(cls, root, info, social, **kwargs)

        if is_thenable(result):
            return Promise.resolve(result).then(on_resolve)
        return on_resolve(result)
    return wrapper
