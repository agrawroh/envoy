Fixed a bug in the HTTP filter where metadata kept a paused stream from resuming. If a module paused
a request or response with a ``StopIteration`` status rather than a ``StopAllIteration`` one and
metadata then reached the filter, as HTTP/2 or HTTP/3 METADATA frames, which ``allow_metadata``
gates, or as metadata another filter added, the module's later ``continue_decoding`` or
``continue_encoding`` call was dropped and the stream waited for its idle timeout. The module's
continue call now resumes the stream.
