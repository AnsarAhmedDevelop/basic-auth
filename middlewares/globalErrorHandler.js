const globalErrorHandler=(err,req, res, next)=>{
    // console.log(err,"error")
      const statusCode= err.status || 500;
      const errorMessage=err.message || 'Internal Server Error'
       const errorDetails = err.errors || []
    res.status(statusCode).json({error:errorMessage,details: errorDetails});
}

export {globalErrorHandler}