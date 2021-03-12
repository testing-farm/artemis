# Type annotations
# pylint: disable=unused-import,wrong-import-order
from typing import TYPE_CHECKING, Any, Dict, List  # noqa


class PrimaryTaskFingerprintsMixin(object):
    """
    The goal of this mixin class is to allow custom "soft" exceptions to implement
    per-component fingerprints. To aggregate soft errors on per-component basis
    is a common demand that it makes sense to provide simple mixin class.

    Simple add it as mixin class to your exception class, and don't forget to accept
    ``task`` parameter:

    .. code-block:: python

       class FooError(PrimaryTaskFingerprintsMixin, SoftGlueError):
           def __init__(self, task):
               super(FooError, self).__init__(task, 'Some weird foo happened')

    :param task: Task in whose context the error happenend. Must provide component
        and ID.
    """

    def __init__(self, task, *args, **kwargs):
        # type: (Any, *Any, **Any) -> None

        super(PrimaryTaskFingerprintsMixin, self).__init__(*args, **kwargs)  # type: ignore  # multiple inheritance

        self.task = task

    def sentry_fingerprint(self, current):
        # type: (List[Any]) -> List[Any]
        # pylint: disable=unused-argument
        """
        Sets Sentry fingerprints to class name and ``task``'s component and ID,
        to force aggregation of errors on a per-component basis.
        """

        # Not calling super - this mixin wants to fully override any possible
        # fingerprints. If you want these fingerprints to coexist with what this
        # mixin provides, do it on your own.

        return [
            self.__class__.__name__,
            self.task.component,
            self.task.id
        ]

    def sentry_tags(self, current):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """
        Adds task namespace and ID as Sentry tags.
        """

        current = super(PrimaryTaskFingerprintsMixin, self).sentry_tags(current)  # type: ignore  # multiple inheritance

        if 'component' not in current:
            current['component'] = self.task.component

        if 'artifact-id' not in current:
            current.update({
                'artifact-namespace': self.task.ARTIFACT_NAMESPACE,
                'artifact-id': self.task.id,
            })

        return current
