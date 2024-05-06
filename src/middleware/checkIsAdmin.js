const { Exception } = require("../module/Exception");
const wrapper = require("../module/wrapper");
const jwt = require("jsonwebtoken");

// const checkIsAdmin = wrapper((req, res, next) => {
//   const { role } = req.session;

//   if (role != 1) {
//     throw new Exception(403, "관리자 권한 없음");
//   }
//   next();
// });

const checkIsAdmin = wrapper((req, res, next) => {
  const { token } = req.headers;
  // console.log("여기?");
  req.decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  if (req.decoded.role != 1) {
    throw new Exception(403, "관리자 권한 없음");
  }

  next();
});

module.exports = { checkIsAdmin };
