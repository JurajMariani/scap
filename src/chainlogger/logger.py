import logging
import logging.handlers

def setupLogger(queue):
    """Setup the logger to send logs to a queue."""
    logger = logging.getLogger('Blockchain Logger')
    logger.setLevel(logging.DEBUG)
    
    # Create a handler that sends log messages to the queue
    # Prevent adding multiple handlers
    if not any(isinstance(h, logging.handlers.QueueHandler) for h in logger.handlers):
        queue_handler = logging.handlers.QueueHandler(queue)
        logger.addHandler(queue_handler)
    
    return logger

def loggerListener(queue, logfile: str = 'log.log'):
    """Process that listens to the queue and writes logs to a file."""
    handler = logging.FileHandler(logfile, mode='w')
    formatter = logging.Formatter('[[%(asctime)s] %(message)s')
    handler.setFormatter(formatter)
    
    logger = logging.getLogger('listener')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    
    while True:
        try:
            # Get log record from the queue
            record = queue.get()
            # Sentinel value to stop the listener
            if record is None:
                break
            logger.handle(record)
        except Exception as e:
            print(f"Error in listener process: {e}")
            break